'use strict';

/**
 * Frida script for Unity IL2CPP games to watch for interesting string constants.
 *
 * Usage example:
 *   frida -U -f com.raongames.bouneball -l frida_item21.js --no-pause
 */

const LIB_IL2CPP = 'libil2cpp.so';

function log(msg) {
  console.log('[item21-trace] ' + msg);
}

function hookIl2CppStringNew() {
  const stringNew = Module.findExportByName(LIB_IL2CPP, 'il2cpp_string_new');
  const stringNewLen = Module.findExportByName(LIB_IL2CPP, 'il2cpp_string_new_len');

  if (!stringNew && !stringNewLen) {
    log('Failed to locate il2cpp_string_new exports. Is the game using IL2CPP?');
    return;
  }

  function installHook(symbol, readFn) {
    if (!symbol) {
      return;
    }
    Interceptor.attach(symbol, {
      onEnter(args) {
        try {
          const str = readFn(args);
          if (!str) {
            return;
          }
          if (str.indexOf('item') !== -1) {
            log(`${symbol.toString()} => ${str}`);
          }
        } catch (err) {
          log('Error reading string: ' + err);
        }
      }
    });
  }

  installHook(stringNew, args => args[0].readCString());
  installHook(stringNewLen, args => {
    const ptr = args[0];
    const len = args[1].toInt32();
    if (ptr.isNull() || len <= 0 || len > 1024) {
      return null;
    }
    return ptr.readUtf8String(len);
  });
}

function hookAddressablesLoadAsset() {
  const resolveIcall = Module.findExportByName(LIB_IL2CPP, 'il2cpp_resolve_icall');
  if (!resolveIcall) {
    log('Unable to find il2cpp_resolve_icall');
    return;
  }

  const unityStringNew = Module.findExportByName(LIB_IL2CPP, 'il2cpp_string_new');
  if (!unityStringNew) {
    log('Cannot resolve il2cpp_string_new for helper wrapper. Skipping Addressables hook.');
    return;
  }

  const icallName = Memory.allocUtf8String('UnityEngine.AddressableAssets.Addressables::LoadAssetAsyncInternal');
  const fnPtr = new NativeFunction(resolveIcall, 'pointer', ['pointer'])(icallName);

  if (fnPtr.isNull()) {
    log('Could not resolve Addressables LoadAssetAsyncInternal. Maybe a different Unity version?');
    return;
  }

  log('Addressables::LoadAssetAsyncInternal resolved at ' + fnPtr);

  Interceptor.attach(fnPtr, {
    onEnter(args) {
      try {
        const keyObj = args[1];
        if (keyObj.isNull()) {
          log('LoadAssetAsyncInternal invoked with null key');
          return;
        }
        const keyString = new Il2CppString(keyObj).toString();
        log('LoadAssetAsyncInternal key = ' + keyString);
      } catch (err) {
        log('Error decoding key: ' + err);
      }
    }
  });
}

// Helper wrapper around UnityEngine.String (Il2CppString)
class Il2CppString {
  constructor(ptr) {
    this.handle = ptr;
  }

  get length() {
    return this.handle.add(Process.pointerSize === 8 ? 0x10 : 0x8).readU32();
  }

  get charPtr() {
    return this.handle.add(Process.pointerSize === 8 ? 0x14 : 0xC);
  }

  toString() {
    const len = this.length;
    if (len === 0) {
      return '';
    }
    return this.charPtr.readUtf16String(len);
  }
}

function main() {
  hookIl2CppStringNew();
  hookAddressablesLoadAsset();
  log('Hooks installed. Waiting for hits...');
}

setImmediate(main);
