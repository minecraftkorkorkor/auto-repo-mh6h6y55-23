'use strict';

/**
 * Frida helpers for inspecting Addressables lookups and managed string creation
 * in Bouncy (Unity / IL2CPP).
 *
 * Example usage:
 *   frida -U -f com.raongames.bouneball -l frida_item21.js --no-pause
 */

const LIB_IL2CPP = 'libil2cpp.so';
const KEYWORDS = ['item21', 'item_21', 'item-21', 'item 21'];

let objectGetClassFn = null;
let classGetNameFn = null;

function log(msg) {
  console.log('[item21-trace] ' + msg);
}

function lowercaseMatch(str) {
  const lowered = str.toLowerCase();
  for (const keyword of KEYWORDS) {
    if (lowered.indexOf(keyword) !== -1) {
      return true;
    }
  }
  return false;
}

function waitForModule(name) {
  return new Promise(resolve => {
    const base = Module.findBaseAddress(name);
    if (base) {
      resolve(base);
      return;
    }

    const callbacks = [];

    function makeHandler(symbol) {
      const address = Module.findExportByName(null, symbol);
      if (!address) {
        return null;
      }

      return Interceptor.attach(address, {
        onEnter(args) {
          try {
            this.path = args[0].readCString();
          } catch (err) {
            this.path = null;
          }
        },
        onLeave(retval) {
          if (retval.isNull()) {
            return;
          }

          try {
            if (this.path && this.path.indexOf(name) !== -1) {
              const base = Module.findBaseAddress(name);
              if (!base) {
                return;
              }
              callbacks.splice(0).forEach(detach => detach());
              log(name + ' loaded at ' + base);
              resolve(base);
            }
          } catch (err) {
            log('Error while watching for ' + name + ': ' + err);
          }
        }
      });
    }

    const detachLater = handler => callbacks.push(() => {
      try {
        handler.detach();
      } catch (err) {}
    });

    const handlers = ['android_dlopen_ext', 'dlopen']
      .map(makeHandler)
      .filter(Boolean);

    if (handlers.length === 0) {
      throw new Error('Unable to find dlopen style exports. Cannot watch for ' + name);
    }

    handlers.forEach(detachLater);
  });
}

function installStringHooks() {
  const stringNew = Module.findExportByName(LIB_IL2CPP, 'il2cpp_string_new');
  const stringNewLen = Module.findExportByName(LIB_IL2CPP, 'il2cpp_string_new_len');
  const stringNewUtf16 = Module.findExportByName(LIB_IL2CPP, 'il2cpp_string_new_utf16');

  if (!stringNew && !stringNewLen && !stringNewUtf16) {
    log('No il2cpp string creation exports found. Skipping string watch.');
    return;
  }

  function attachIfAvailable(symbol, reader, description) {
    if (!symbol) {
      return;
    }

    Interceptor.attach(symbol, {
      onEnter(args) {
        try {
          const value = reader(args);
          if (!value) {
            return;
          }
          if (lowercaseMatch(value)) {
            log(description + ' => ' + value);
          }
        } catch (err) {
          log('Error decoding managed string: ' + err);
        }
      }
    });

    log('Watching ' + description + ' at ' + symbol);
  }

  attachIfAvailable(stringNew, args => {
    const ptr = args[0];
    if (ptr.isNull()) {
      return null;
    }
    return Memory.readUtf8String(ptr);
  }, 'il2cpp_string_new');

  attachIfAvailable(stringNewLen, args => {
    const ptr = args[0];
    const len = args[1].toInt32();
    if (ptr.isNull() || len <= 0 || len > 2048) {
      return null;
    }
    return Memory.readUtf8String(ptr, len);
  }, 'il2cpp_string_new_len');

  attachIfAvailable(stringNewUtf16, args => {
    const ptr = args[0];
    const len = args[1].toInt32();
    if (ptr.isNull() || len <= 0 || len > 2048) {
      return null;
    }
    return Memory.readUtf16String(ptr, len);
  }, 'il2cpp_string_new_utf16');
}

function readIl2CppString(strPtr) {
  if (!strPtr || strPtr.isNull()) {
    return null;
  }

  try {
    const sizeOffset = Process.pointerSize === 8 ? 0x10 : 0x8;
    const dataOffset = Process.pointerSize === 8 ? 0x14 : 0xC;
    const length = strPtr.add(sizeOffset).readU32();
    if (length === 0) {
      return '';
    }
    return strPtr.add(dataOffset).readUtf16String(length);
  } catch (err) {
    log('Failed to read managed string at ' + strPtr + ': ' + err);
    return null;
  }
}

function getObjectClassName(ptr) {
  if (!objectGetClassFn || !classGetNameFn) {
    return null;
  }

  try {
    const klass = objectGetClassFn(ptr);
    if (klass.isNull()) {
      return null;
    }

    const namePtr = classGetNameFn(klass);
    if (namePtr.isNull()) {
      return null;
    }

    return Memory.readUtf8String(namePtr);
  } catch (err) {
    log('Unable to determine class name: ' + err);
    return null;
  }
}

function installAddressablesHook() {
  const resolveIcall = Module.findExportByName(LIB_IL2CPP, 'il2cpp_resolve_icall');
  if (!resolveIcall) {
    log('il2cpp_resolve_icall not found. Unable to hook Addressables.');
    return;
  }

  const resolve = new NativeFunction(resolveIcall, 'pointer', ['pointer']);
  const icallName = Memory.allocUtf8String('UnityEngine.AddressableAssets.Addressables::LoadAssetAsyncInternal');
  const target = resolve(icallName);

  if (target.isNull()) {
    log('Addressables::LoadAssetAsyncInternal not resolved (possibly stripped in this build).');
    return;
  }

  log('Hooking Addressables::LoadAssetAsyncInternal at ' + target);

  Interceptor.attach(target, {
    onEnter(args) {
      try {
        const keyObject = args[1];
        if (keyObject.isNull()) {
          log('LoadAssetAsyncInternal(null)');
          return;
        }

        const asString = readIl2CppString(keyObject);
        if (asString) {
          log('LoadAssetAsyncInternal key => ' + asString);
          return;
        }

        const className = getObjectClassName(keyObject) || 'UnknownType';
        log('LoadAssetAsyncInternal key object type: ' + className + ' @ ' + keyObject);
      } catch (err) {
        log('Error inside Addressables hook: ' + err);
      }
    }
  });
}

function installHooks() {
  const getClassPtr = Module.findExportByName(LIB_IL2CPP, 'il2cpp_object_get_class');
  const getNamePtr = Module.findExportByName(LIB_IL2CPP, 'il2cpp_class_get_name');

  if (getClassPtr && getNamePtr) {
    objectGetClassFn = new NativeFunction(getClassPtr, 'pointer', ['pointer']);
    classGetNameFn = new NativeFunction(getNamePtr, 'pointer', ['pointer']);
  } else {
    objectGetClassFn = null;
    classGetNameFn = null;
  }

  installStringHooks();
  installAddressablesHook();
  log('Hooks installed. Waiting for matches...');
}

function main() {
  log('Waiting for ' + LIB_IL2CPP + ' to be ready...');
  waitForModule(LIB_IL2CPP)
    .then(() => {
      try {
        const base = Module.findBaseAddress(LIB_IL2CPP);
        if (base) {
          Module.ensureInitialized(base);
        }
      } catch (err) {
        log('Module.ensureInitialized failed (continuing anyway): ' + err);
      }
      installHooks();
    })
    .catch(err => {
      log('Failed while waiting for ' + LIB_IL2CPP + ': ' + err);
    });
}

setImmediate(main);
