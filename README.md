# MaxPatrolSIEM
## Архитектура Siem и VM
![image](https://github.com/user-attachments/assets/dbec4793-6ffe-4191-bb4f-a76d859b0fd6)
### MP 10 Core состоит из нескольких элементов:
MaxPatrol 10 отвечает за работу с активами и событиями
PT MC - менеджмент и конфигурэтион, хранит учётные записи и отвечает за утентификацию в овнешних системах
PT KB - база знаний, в которой хранится информация о уязвимостях и инф. о правилах нормализации, корреляции и т.д.
Core содержит базу данных(PostgeSQL) в которой хранятся:
1. Все сделанные в системе настройки(профили сбора событий, настроенные уведомления и т.д)
2. УЗ для авторизации в сием и настройки с внешними ldap
3. УЗ для аудита и сборы событий
4. Инф о событиях
5. Инцеденты
6. Задачи в рамках работы над инцедентом
### MP SIEM Server осуществляет обработку событий: нормализацию, корреляцию, обогощение и т.д
К нему обращаются другие компоненты
### MP SIEM Events Storage хранилише состоящие из ELK search или logspace(туда можно тольок дописывать информацию, изменять нельзя)
### Агенты, которые собирают какую-лиюо информацию, которую направляют в сием
![image](https://github.com/user-attachments/assets/40b1c468-c078-4712-b91b-08740430499e)
## Устаовка MaxPatrol SIEM
![image](https://github.com/user-attachments/assets/abe889c2-772a-42f3-bc59-2f3add805f2d)
Проверить запущенные сервисы, которые сидят в докер контейнере, перезапустить контейнер:
```
sudo docker ps
sudo docker restart $(sudo docker ps | awk '/licensing/{print $NF}') 
sudo docker restart $(sudo docker ps | awk '$NF~"core-|kb-"{print $NF}') #всё что имеет в название core или kb
```

Host discovery - проверяет только жив или нет  
Inventory discovery - больше портов и пытается определить OS  
Host.OsName like 'WIndows%' # % как * в линукc  
Host.OsName match 'Debian|Ubuntu|RedHat|Mandr(ake|iva)' # регулярка которая будет искать совпадение: дебиан или убунту или Mandrake или Mandriva  
Host.@IPAddresses.Item in 10.0.1.64/26 # показывает все хосты в подсеткe  
Host.Softs[Name = 'OpenSSL' and @VULNERS ] # ищем софт OpenSSL и чтобы он был уязвимым(@VULNERS = уязвимость true)  
Host.@Vulners.CVEs intersect ['CVE-2017-0143', 'CVE-2017-0144'] хост должен быть подвержен обеим уязвимостям, тогда возвращает true  
Host.@Vulners.CVEs.Item match "CVE-2017-014[3-8]" match работает с регуляркой, т.е будет искать хост где есть все уязвимости с 0143 по 0148  
Host.@Vulners.CVSS3TEMPORALVECTOR like "E:F%"  
## Таксономия  
![image](https://github.com/user-attachments/assets/d3d62efe-ea22-4ebc-8aa8-008607378dd3)  
Поле body - raw(сырое) событие string  
Historical обязательное поле - true - устаревшее событие, false - Обычное; boolean  
Generator.version - версия компонента, от которого пришло событие string  
Generator.type - названние компонента, от которого пришло событие enum  
normolized - true/false нормализация bool  
recv_host - название узла, от куда пришло событие(string) "Name1" string  
recv_ipv4 - ipv4 узла, от которого получено событие(если стоит наттранслятор, то будет его айпи) IPAddress  
tag - модуль агента, получившего необработанное событие, например, tag="syslog" string  
recv_time - время поллучения события агетом MaxPatrol SIEM DateTime  
id - идентификаитор правил нормализации и корреляции, значение может быть неуникальным, тип string  
![image](https://github.com/user-attachments/assets/ffb34a79-645f-4e23-a693-b5d722857458)  
importance - info. low, medium. high, заполняется автоматически исходя из id enum  
correlation_name - название правила корреляции, с помощью которого выявлено событие string  
aggregation_name - название правила агреггации string  
correlation_type = enum event or incedent







