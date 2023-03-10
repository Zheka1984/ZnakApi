Для запуска тестов следует:

1) инсталлировать CryptoPro JCP.
2) сформировать ключ и сертификат клиента на алгоритме ГОСТ Р 34.10.
3) запустить IDE Eclipse, создать пустой проект и поместить в папку src папку ru со всеми содержащимися в ней папками и файлами. В свойствах проекта следует добавить путь к jar-файлам wss4j 1.5.11:
axis-1.4.jar
axis-ant-1.4.jar
axis-jaxrpc-1.4.jar
axis-saaj-1.4.jar
bcprov-jdk14-1.45.jar
commons-codec-1.3.jar
commons-discovery-0.2.jar
commons-logging-1.1.jar
junit-3.8.1.jar
log4j-1.2.9.jar
opensaml-1.1.jar
serializer-2.7.1.jar
wss4j-1.5.11.jar
xalan-2.7.1.jar
xmlsec-1.4.4.jar

4) В папке с проектом должен быть создан каталог WebContent/resources, в него помещен файл crypto.properties с необходимыми настройками. Например:

org.apache.ws.security.crypto.provider=ru.wss4j1_5_11.ws.security.components.crypto.MerlinEx
org.apache.ws.security.crypto.merlin.keystore.type=HDImageStore
org.apache.ws.security.crypto.merlin.keystore.password=my_password
org.apache.ws.security.crypto.merlin.keystore.alias=my_key_store
cert.file=path_to_cert
ca.file=path_to_ca
crl.file=path_to_crl

,где my_password - пароль для доступа к контейнеру, 
my_key_store - название контейнера (alias), 
path_to_cert - путь к сертификату, соответствующему my_key_store,
path_to_ca - путь к корневому сертификату для path_to_cert,
path_to_crl - путь к CRL файлу.

Примечание #1:
также может присутствовать параметр org.apache.ws.security.crypto.merlin.file.

Примечание #2:
в файле ru.utility.SpecUtility имеется ряд переменных, которые загружаются из {user.dir}/WebContent/resources/crypto.properties.

Внимание! Если возникло исключение типа algorithm already registered, class not found (serializer, uri, looger) то необходимо поместить в папку с установленным CryptoPro JCP (jre/lib/ext) файлы:
commons-logging-1.1.jar
serializer-2.7.1.jar
xalan-2.7.1.jar
xmlsec-1.4.4.jar

##################################################################################################

Описание пакетов:

ru.manager.* - классы с описанием потоков, тестирующих функции формирования/проверки ЭЦП XML SOAP.
ru.wss4j1_5_11.ws.security.components.crypto - содержит расширенный класс MerlinEx.
ru.wss4j1_5_11.tests - пакет с тестами производительности JCP.
ru.wss4j1_5_11.manager.SOAPXMLSignatureManager_1_5_11 - класс примера формирования XML SOAP документа, подписания и проверки ЭЦП.

##################################################################################################

Описание тестов производительности:

1. Добавлен потомок MerlinEx класса Merlin для кэширования закрытого ключа и ускорения подписания. Соответственно, изменен параметр org.apache.ws.security.crypto.provider в файле crypto.properties. Его новое значение:
org.apache.ws.security.crypto.provider=ru.wss4j1_5_11.ws.security.components.crypto.MerlinEx

2. Добавлены несколько видов тестов для оценки скорости подписывания и проверки ЭЦП (ru.wss4j1_5_11.tests). 
Увеличение числа потоков может привести к росту производительности.

 А. EfficiencyTestSingle оценивает скорость формирования и проверки ЭЦП в SOAP XML, выполняемых одна за другой в одном блоке в последовательном цикле в главном потоке приложения; дается более точная оценка времени выполнения каждой операции (op/s) и средняя скорость выполнения (op/s).
Пример для цикла из 1000 итераций 
1) Средняя скорость пары операций: 45 оп/с (Windows 7 32-b., 1-яд. проц., 2 Гб ОЗУ)
2) Средняя скорость операции подписывания: 34.5 оп/с (Windows 7 32-b., 1-яд. проц., 2 Гб ОЗУ)
3) Средняя скорость операции проверки ЭЦП: 70 оп/с (Windows 7 32-b., 1-яд. проц., 2 Гб ОЗУ)

 Б. EfficiencyTestCombined оценивает скорость формирования и проверки ЭЦП в SOAP XML, выполняемых одна за другой в одном блоке в разных потоках; кол-во потоков можно менять; дается средняя скорость выполнения (op/s) операций, причем она выше скорости в EfficiencyTestSingle. 
Пример для 10 запущенных потоков 
1) Средняя скорость пары операций: 84 оп/с (Windows 7 32-b., 1-яд. проц., 2 Гб ОЗУ)
2) Средняя скорость операции подписывания: 65 оп/с (Windows 7 32-b., 1-яд. проц., 2 Гб ОЗУ)
3) Средняя скорость операции проверки ЭЦП: 120 оп/с (Windows 7 32-b., 1-яд. проц., 2 Гб ОЗУ)

 В. EfficiencyTestMulti оценивает скорость формирования и проверки ЭЦП в SOAP XML, выполняемых независимо друг от друга в разных потоках, но синхронизированных по очереди сообщений; кол-во потоков можно менять; дается средняя скорость выполнения (op/s) операций, которая приближается к аналогичной скорости в EfficiencyTestSingle из-за синхронизации потоков по одной общей для всех потоков очереди.
Пример для 5 потоков-подписчиков и 5 потоков-проверяльщиков (10 потоков)
1) средняя скорость пары операций: 45 оп/с (Windows 7 32-b., 1-яд. проц., 2 Гб ОЗУ)
2) средняя скорость операции подписывания: 35 оп/с (Windows 7 32-b., 1-яд. проц., 2 Гб ОЗУ)
3) средняя скорость операции проверки ЭЦП: 70 оп/с (Windows 7 32-b., 1-яд. проц., 2 Гб ОЗУ)

 Г. EfficiencyTestMultiQueue оценивает скорость формирования и проверки ЭЦП в SOAP XML, выполняемых независимо друг от друга в разных потоках, но синхронизированных попарно по своей очереди сообщений (поток-подписчик и поток-проверяльщик имеют одну общую очередь, таких пар может быть несколько); кол-во пар потоков можно менять; дается средняя скорость выполнения (op/s) операций, которая приближается к аналогичной скорости в EfficiencyTestCombined из-за синхронизации пар потоков по их общей очереди и может выше.
Пример для 5 пар потоков-подписчиков и потоков-проверяльщиков (10 потоков)
1) средняя скорость пары операций: 83 оп/с (Windows 7 32-b., 1-яд. проц., 2 Гб ОЗУ)
2) средняя скорость операции подписывания: 62 оп/с (Windows 7 32-b., 1-яд. проц., 2 Гб ОЗУ)
3) средняя скорость операции проверки ЭЦП: 115 оп/с (Windows 7 32-b., 1-яд. проц., 2 Гб ОЗУ)

3. Добавление класса SOAPXMLSignatureManager_1_5_11 для формирования и проверки ЭЦП в SOAP XML документах и для использования его в простых примерах, выполняющихся в главном потоке (например, в тесте WSS4J_SignVerifySOAP).

4. Пример для разового подписывания/проверки ЭЦП SOAP XML документа в пакет ru.wss4j1_5_11.tests: WSS4J_SignVerifySOAP.

##################################################################################################

Описание проверки цепочки доверия:

1. Примеры для проверки цепочки сертификатов в пакете ru.wss4j1_5_11.tests: ValidateCertificateChain.
Представлены 2 метода:
1) функции проверки цепочки сертификатов с CRL (runTestRSA - для ключей RSA, runTestGOST - для ключей ГОСТ Р 34.10). Сертификаты загружаются из ключевого контейнера или файлов.
2) пример применения метода validateCertPath из интерфейса Crypto (CRL отключен) (runTestRSA_IfCAIsInCacertsAndIfUseMerlinByProperties и
runTestGOST_IfCAIsInCacertsAndIfUseMerlinByProperties). Сертификаты загружаются из ключевого контейнера и хранилища корневых сертификатов JRE_HOME/lib/security/cacerts.

##################################################################################################

Дополнительные функции:

1. Добавлена проверка версии библиотеки wss4j в пакет ru.SOAPUtility.

	if ( !is_1_5_11(props.getProperty("org.apache.ws.security.crypto.provider")) ) {
		System.out.println("WSS4J is not 1.5.11.");
		return;
	}