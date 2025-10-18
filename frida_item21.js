'use strict';

/**
 * Bouncy (Unity / IL2CPP) Addressables 및 문자열 추적을 위한 Frida 스크립트.
 *
 * 실행 예시 (USB 디버깅, 앱을 Frida가 시작하도록 할 때):
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

function findModuleBase(name) {
  if (typeof Module !== 'undefined') {
    if (typeof Module.findBaseAddress === 'function') {
      const base = Module.findBaseAddress(name);
      if (base) {
        return base;
      }
    } else {
      log('Module.findBaseAddress 미지원: Process API로 대체합니다.');
    }
  }

  if (typeof Process !== 'undefined') {
    if (typeof Process.findModuleByName === 'function') {
      try {
        const moduleInfo = Process.findModuleByName(name);
        if (moduleInfo) {
          return moduleInfo.base;
        }
      } catch (err) {
        if (String(err).indexOf('not found') === -1) {
          throw err;
        }
      }
    }

    if (typeof Process.enumerateModules === 'function') {
      const modules = Process.enumerateModules();
      for (const moduleInfo of modules) {
        if (moduleInfo.name === name) {
          return moduleInfo.base;
        }
      }
    }
  }

  return null;
}

function waitForModule(name, { pollIntervalMs = 100, timeoutMs = 0 } = {}) {
  const start = Date.now();

  while (true) {
    const base = findModuleBase(name);
    if (base) {
      log(name + ' loaded at ' + base);
      return base;
    }

    if (timeoutMs > 0 && Date.now() - start > timeoutMs) {
      throw new Error('Timed out waiting for ' + name);
    }

    if (typeof Thread !== 'undefined' && typeof Thread.sleep === 'function') {
      Thread.sleep(pollIntervalMs / 1000);
    } else {
      const deadline = Date.now() + pollIntervalMs;
      while (Date.now() < deadline) {}
    }
  }
}

function installStringHooks() {
  const stringNew = Module.findExportByName(LIB_IL2CPP, 'il2cpp_string_new');
  const stringNewLen = Module.findExportByName(LIB_IL2CPP, 'il2cpp_string_new_len');
  const stringNewUtf16 = Module.findExportByName(LIB_IL2CPP, 'il2cpp_string_new_utf16');

  if (!stringNew && !stringNewLen && !stringNewUtf16) {
    log('il2cpp 문자열 생성 심볼을 찾을 수 없습니다. 문자열 감시는 건너뜁니다.');
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
          log('문자열 디코딩 실패: ' + err);
        }
      }
    });

    log(description + ' 감시 중 @ ' + symbol);
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
    log('IL2CPP 문자열 읽기 실패 @ ' + strPtr + ': ' + err);
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
    log('클래스 이름 확인 실패: ' + err);
    return null;
  }
}

function installAddressablesHook() {
  const resolveIcall = Module.findExportByName(LIB_IL2CPP, 'il2cpp_resolve_icall');
  if (!resolveIcall) {
    log('il2cpp_resolve_icall 미발견: Addressables 후킹 불가.');
    return;
  }

  const resolve = new NativeFunction(resolveIcall, 'pointer', ['pointer']);
  const icallName = Memory.allocUtf8String('UnityEngine.AddressableAssets.Addressables::LoadAssetAsyncInternal');
  const target = resolve(icallName);

  if (target.isNull()) {
    log('Addressables::LoadAssetAsyncInternal 해석 실패 (스트립 되었을 수 있음).');
    return;
  }

  log('Addressables::LoadAssetAsyncInternal 후킹 @ ' + target);

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
          log('LoadAssetAsyncInternal 키 => ' + asString);
          return;
        }

        const className = getObjectClassName(keyObject) || 'UnknownType';
        log('LoadAssetAsyncInternal 키 객체 타입: ' + className + ' @ ' + keyObject);
      } catch (err) {
        log('Addressables 후킹 내부 오류: ' + err);
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
  log('후킹 완료. item21 관련 문자열을 대기 중입니다.');
}

function main() {
  log(LIB_IL2CPP + ' 로딩을 대기합니다...');
  try {
    const base = waitForModule(LIB_IL2CPP);
    if (base && typeof Module.ensureInitialized === 'function') {
      try {
        Module.ensureInitialized(base);
      } catch (err) {
        log('Module.ensureInitialized 실패 (무시하고 진행): ' + err);
      }
    }
    installHooks();
  } catch (err) {
    log(LIB_IL2CPP + ' 대기 중 오류: ' + err);
  }
}

setImmediate(main);
