# Wire Shark (MFC Packet Sniffer)

**this project need winpcap library! please install winpcap!** 

* ver 1.1.0
1. 메인 화면 UI 변경
2. 필터 작동 오류 문제 수정
3. 상단 메뉴에 화면 이동 기능 추가
4. 기타 품질 개선을 위한 버그 수정

* ver 1.0.1  
필터 기능 추가  
**port == 80**  
**port == 80 or ip == 127.0.0.1**  
**ip == 127.0.0.1**  
**ip == 192.168.0.1 and port == 65536**  
**(ip == 192.168.0.1 and port == 65536) and tcp** (작동 안되도록 함)   
**(port == 65536 and ip == 192.168.0.1) and udp**  (작동 안되도록 함)   
**length == 60**  
**length >= 60**  
**length <= 60**  
**length > 60**  
**length < 60**  
	
* ver 1.0.1  
`TCP, UDP, ARP, ICMP`  4가지 종류 패킷 캡처 가능(추가 업데이트 예정)  
	
	
* Interface Select Wnd
<img src="/Image/SelectNetInfWnd.PNG" width="500" height="250">

* ver 1.0.1 Main UI (new)
<img src="/Image/MainWnd2.PNG" width="1000" height="500">

* ver 1.0.0 Main UI (old)
<img src="/Image/MainWnd.PNG" width="900" height="750">
