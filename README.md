# Computer-security-final-lab
**Security issue : CVE-2026-21643 on FortiClient EMS 7.4.4** 

**WARNING**: \
*To run the mock system you may need some module and lib for js and python. Here are the useful link.*\
To download the sql lib follow this [link](https://github.com/sql-js/sql.js.git).\
To download the express module for js use this [link](https://expressjs.com/en/).


**How to run the mock system** : \
To start the server run the cmd : \
```node server.js ``` \
To use the exploit run the cmd : \
```python3 presentation_exploit.py -i index_exploit``` \
The option -i is an optional integer, to know the different option run : \
```python3 presentation_exploit.py -nh yes``` \
Obviously you need to start the server before using the exploit file... \
The mock server will be available at : [http://localhost:3000](http://localhost:3000).


**useful link** : \
[overleaf](https://sharelatex.tum.de/2654279458wnzqdwsnqmpp#e78ff3) \
[exploit-git-example](https://github.com/alirezac0/CVE-2026-21643/blob/main/cve_2026_21643.py) \
[exploit-git-example-2](https://github.com/0xBlackash/CVE-2026-21643/blob/main/cve-2026-21643.py) \
[our-git](https://github.com/Gousse-Gousse/Computer-security-final-lab.git) \
[NIST-report](https://nvd.nist.gov/vuln/detail/CVE-2026-21643) \
[bishop-fox-well-detailed-report](https://bishopfox.com/blog/cve-2026-21643-pre-authentication-sql-injection-in-forticlient-ems-7-4-4) \
[git-for-sql](https://github.com/sql-js/sql.js.git) 
[epress-module-lib](https://expressjs.com/en/)