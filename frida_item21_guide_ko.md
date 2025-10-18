# Frida item21 추적 스크립트 사용법

이 저장소에는 `frida_item21.js` 스크립트가 포함되어 있으며, Bouncy(Android)에서 `item21` 관련 Addressables 키와 문자열을 실시간으로 확인할 수 있습니다. 다음 명령 예시는 USB 디버깅이 활성화된 기기에서 앱을 Frida가 직접 시작하도록 구성되어 있습니다.

```bash
frida -U -f com.raongames.bouneball -l frida_item21.js --no-pause
```

이미 실행 중인 프로세스에 붙고 싶다면 다음과 같이 PID나 앱 패키지명을 지정할 수 있습니다.

```bash
# 실행 중인 프로세스를 Frida가 나열하도록 확인
frida-ps -U | grep bouneball

# 프로세스에 직접 후킹
frida -U -n com.raongames.bouneball -l frida_item21.js
```

장치가 TCP/IP로 연결된 경우 `adb connect <IP>:<PORT>` 후 `-R` 옵션을 사용합니다.

```bash
# 예시: 무선 ADB 접속 후 Frida 원격 세션
adb connect 192.168.45.15:6556
frida -R 192.168.45.15:27042 -f com.raongames.bouneball -l frida_item21.js --no-pause
```

## 출력 예시

스크립트는 다음과 같은 로그를 출력합니다.

```
[item21-trace] libil2cpp.so 로딩을 대기합니다...
[item21-trace] libil2cpp.so loaded at 0x7c12345678
[item21-trace] Addressables::LoadAssetAsyncInternal 후킹 @ 0x7c0abc0000
[item21-trace] LoadAssetAsyncInternal 키 => item21_reward_bundle
```

키가 문자열이 아닌 다른 객체일 때는 객체의 IL2CPP 클래스명을 표시합니다.

## 문제 해결 팁

- `Module.findBaseAddress`가 제공되지 않는 구형 Frida 버전에서도 동작하도록 `Process.findModuleByName`/`enumerateModules` 기반 폴백을 사용합니다.
- `libil2cpp.so`가 압축 또는 보호되어 바로 로드되지 않는 경우에는 스크립트가 로딩될 때까지 반복 대기하므로 추가 타이머 설정이 필요하지 않습니다.
- 로그가 지나치게 많다면 `KEYWORDS` 배열에 필요한 문자열만 남겨 필터링 강도를 높이세요.
