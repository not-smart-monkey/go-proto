Быстрый набросок простого многопоточного GO сканера портов на примере `scanme.nmap.org`
Работа не завершена на данный момент, но уже все работает

Пример запуска:
```bash 
go run main.go
```

Output:
```bash
$ go run main.go
[==                                                ] 572/10000 (5.7%) | Open: [22 80]^C
Received interrupt signal, initiating graceful shutdown...

Scan Report
-----------
Scanned ports: 573/10000
Open ports: 2
List of open ports: [22 80]
Scan duration: 9.94 seconds
```