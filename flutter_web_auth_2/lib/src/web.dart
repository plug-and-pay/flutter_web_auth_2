import 'dart:async';
import 'dart:convert';
import 'dart:js_interop';

import 'package:flutter/services.dart';
import 'package:flutter_web_auth_2/src/options.dart';
import 'package:flutter_web_auth_2_platform_interface/flutter_web_auth_2_platform_interface.dart';
import 'package:flutter_web_plugins/flutter_web_plugins.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:web/web.dart';

/// Implements the plugin interface using iframes (for silent authentication)
/// and through an event listener system (for usual authentication).
class FlutterWebAuth2WebPlugin extends FlutterWebAuth2Platform {
  Completer<String>? _completer;
  Timer? _lsTimer;
  Timer? _responseTimeoutTimer;
  StreamSubscription? _messageSubscription;
  HTMLIFrameElement? _authIframe;
  String? _windowName;

  /// Registers the web implementation.
  static void registerWith(Registrar registrar) {
    final channel = MethodChannel(
      'flutter_web_auth_2',
      const StandardMethodCodec(),
      registrar,
    );
    final instance = FlutterWebAuth2WebPlugin();
    channel.setMethodCallHandler(instance._handleMethodCall);
    FlutterWebAuth2Platform.instance = instance;
  }

  Future<dynamic> _handleMethodCall(MethodCall call) async {
    switch (call.method) {
      case 'authenticate':
        final url = call.arguments['url'].toString();
        return authenticate(
          url: url,
          callbackUrlScheme: '',
          options: call.arguments['options'],
        );
      case 'cleanUpDanglingCalls':
        return clearAllDanglingCalls();
      case 'close':
        return close();
      default:
        throw PlatformException(
          code: 'Unimplemented',
          details: "The flutter_web_auth_2 plugin for web doesn't implement "
              "the method '${call.method}'",
        );
    }
  }

  @override
  Future<String> authenticate({
    required String url,
    required String callbackUrlScheme,
    required Map<String, dynamic> options,
  }) async {
    final parsedOptions = FlutterWebAuth2Options.fromJson(options);

    if (parsedOptions.silentAuth) {
      final authIframe = (document.createElement('iframe') as HTMLIFrameElement)
        ..src = url
        ..style.display = 'none';

      document.body?.append(authIframe);

      final completer = Completer<String>();
      _completer = completer;
      _authIframe = authIframe;

      _messageSubscription = window.onMessage.listen((messageEvent) {
        if (messageEvent.origin ==
            (parsedOptions.debugOrigin ?? Uri.base.origin)) {
          final data = messageEvent.data.dartify();
          final authMessage =
              data != null && data is Map ? data['flutter-web-auth-2'] : null;
          if (authMessage is String) {
            authIframe.remove();
            _authIframe = null;
            if (!completer.isCompleted) {
              completer.complete(authMessage);
            }
            _responseTimeoutTimer?.cancel();
            _responseTimeoutTimer = null;
            _messageSubscription?.cancel();
            _messageSubscription = null;
            _completer = null;
          }
        }
      });

      // Add a timeout for the iframe response
      _responseTimeoutTimer =
          Timer(Duration(seconds: parsedOptions.timeout), () {
        authIframe.remove();
        _authIframe = null;
        _messageSubscription?.cancel();
        _messageSubscription = null;
        if (!completer.isCompleted) {
          completer.completeError(
            PlatformException(
              code: 'timeout',
              message: 'Timeout waiting for the iframe response',
            ),
          );
        }
        _completer = null;
      });

      return completer.future;
    }

    await launchUrl(
      Uri.parse(url),
      webOnlyWindowName: parsedOptions.windowName,
    );
    _windowName = parsedOptions.windowName;

    // Remove the old record if it exists
    const storageKey = 'flutter-web-auth-2';
    window.localStorage.removeItem(storageKey);
    final completer = Completer<String>();
    _completer = completer;
    try {
      // Periodically check for the callback value in local storage.
      // If it exists, return it. If not, check the timeout.
      // If the timeout has passed, throw an exception.
      _lsTimer = Timer.periodic(const Duration(seconds: 1), (timer) {
        final flutterWebAuthMessage = window.localStorage.getItem(storageKey);
        if (flutterWebAuthMessage != null) {
          if (!completer.isCompleted) {
            completer.complete(flutterWebAuthMessage);
          }
          window.localStorage.removeItem(storageKey);
          _messageSubscription?.cancel();
          _messageSubscription = null;
          timer.cancel();
          _lsTimer = null;
          _completer = null;
        } else if (timer.tick >= parsedOptions.timeout) {
          _messageSubscription?.cancel();
          _messageSubscription = null;
          timer.cancel();
          _lsTimer = null;
          if (!completer.isCompleted) {
            completer.completeError(
              PlatformException(
                code: 'error',
                message: 'Timeout waiting for callback value',
              ),
            );
          }
          _completer = null;
        }
      });

      // Traditional window.opener method of listening for the redirect
      _messageSubscription = window.onMessage.listen(
        (messageEvent) {
          if (messageEvent.origin ==
              (parsedOptions.debugOrigin ?? Uri.base.origin)) {
            final data = messageEvent.data.dartify();
            final flutterWebAuthMessage =
                data != null && data is Map ? data['flutter-web-auth-2'] : null;
            if (flutterWebAuthMessage is String) {
              _lsTimer?.cancel();
              _lsTimer = null;
              _messageSubscription?.cancel();
              _messageSubscription = null;
              if (!completer.isCompleted) {
                completer.complete(flutterWebAuthMessage);
              }
              _completer = null;
            }
          }

          final appleOrigin = Uri(scheme: 'https', host: 'appleid.apple.com');
          if (messageEvent.origin == appleOrigin.toString()) {
            try {
              final data = jsonDecode(messageEvent.data.toString());
              if (data['method'] == 'oauthDone') {
                final appleAuth =
                    data['data']['authorization'] as Map<String, dynamic>?;
                if (appleAuth != null) {
                  final appleAuthQuery = Uri(queryParameters: appleAuth).query;
                  _lsTimer?.cancel();
                  _lsTimer = null;
                  _messageSubscription?.cancel();
                  _messageSubscription = null;
                  if (!completer.isCompleted) {
                    completer.complete(
                      appleOrigin.replace(fragment: appleAuthQuery).toString(),
                    );
                  }
                  _completer = null;
                }
              }
            } on FormatException {
              // ignore exception
            }
          }
        },
        onError: (error) {
          _lsTimer?.cancel();
          _lsTimer = null;
          _messageSubscription?.cancel();
          _messageSubscription = null;
          throw error;
        },
      );
    } catch (e) {
      _lsTimer?.cancel();
      _lsTimer = null;
      if (!completer.isCompleted) {
        completer.completeError(e);
      }
      _completer = null;
    }

    return completer.future;
  }

  @override
  Future<void> clearAllDanglingCalls() async {}

  @override
  Future<void> close() async {
    _lsTimer?.cancel();
    _lsTimer = null;
    _responseTimeoutTimer?.cancel();
    _responseTimeoutTimer = null;
    await _messageSubscription?.cancel();
    _messageSubscription = null;
    _authIframe?.remove();
    _authIframe = null;

    // Best-effort attempt to close a popup we opened via launchUrl. Browsers
    // generally only allow closing a window that the current script opened
    // and still holds a reference to; window.open with an existing name may
    // return a handle we can close.
    final windowName = _windowName;
    if (windowName != null && windowName.isNotEmpty) {
      try {
        window.open('', windowName)?.close();
      } catch (_) {
        // ignore — popup ownership may have been lost
      }
    }
    _windowName = null;

    final completer = _completer;
    if (completer != null && !completer.isCompleted) {
      completer.completeError(
        PlatformException(
          code: 'CANCELED',
          message: 'Session closed by app',
        ),
      );
    }
    _completer = null;
  }
}
