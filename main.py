import sys
from threading import Thread
from threading import Lock
from queue import Queue

from PortScanners.NmapPortScanner import NmapScanner
from Parsers.GeneratorOfParsers import ParserGenerator
from VulnFinders.FinderFactory import VulnScannersFactory


class VulnApplicationManager:
    '''
    Менеджер управления приложением
    Создаёт сканеры портов, парсеры, обрабатывает результаты их работы
    При наличии информации об активных сервисах, передаёт её далее к поиску в бд
    '''
    
    def __init__(self, host:str, portScanner:object, scList:list):
        self.__portScanner = portScanner(host, ["-sV"])
        self.__host = host
        self.__vulnScFactories = scList     
        self.__vulnScanners = []
        self.__results = []
    
    def run(self) -> dict:
        '''
        Основная функция, запускающая поиск уязвимостей в отдельных потоках для каждого сканера
        Возвращает словарь с проверяемыми хостами и найденными уязвимостями
        '''
        services = self.__findActiveServices()
        activeThreads = Queue()
        
        if not services:
            return None
        else:
            for vulnScanner in self.__createVulnFinders(services):
                thread = Thread(target=self.__findVulnerabilities, args=(vulnScanner,))
                thread.start()
                
                activeThreads.put(thread)
            
            while not activeThreads.empty():
                thread = activeThreads.get()
                thread.join()
            
            return self.__compareResults()
            
    def __findVulnerabilities(self, vulnScanner:object):
        '''
        Запуск сканера на поиск уязвимостей,
        при завершении работы сканера использует Lock для доступа к основному списку результатов
        '''
        
        vulnScanner.loadVulnerabilitiesDatabase()
        scanResult = vulnScanner.findVulnerabilities()  # ГЛАВНЫЙ ВЫВОД ПРОГРАММЫ НА ДАННЫЙ МОМЕНТ
        
        lock = Lock()
        
        with lock:
            self.__results.append(scanResult)
                
    
    def __findActiveServices(self) -> dict:
        '''
        Проводит первичное сканирование портов цели и формирует из результата
        необходимый словарь с помощью парсеров
        '''
        portList = self.__portScanner.createPortList()
        
        if not portList:
            print("Scanner didn't find anything")
            return None
        else:
            serviceParser = ParserGenerator.createParser("services")
            serviceParser.loadData(portList)
            serviceInfo = serviceParser.parseData()

            return serviceInfo
    
    def __createVulnFinders(self, serviceData:str) -> object:
        '''
        С помощью списка фабрик создаёт сканеры уязвимостей,
        передаёт в них информацию об активных сервисах
        '''
        for vulnScFactory in self.__vulnScFactories:
            print(vulnScFactory)
            vulnSc = vulnScFactory.createScanner(serviceData)
            
            yield vulnSc
    
    def __compareResults(self) -> dict:
        '''
        Перебирает все полученные результаты от каждого сканера и убирает повторяющиеся уязвимости
        Возвращает словарь с найденными уязвимостями со всех сканеров
        '''
        finalVulnerabilities = {}
        
        for resOfScanner in self.__results:
            
            for foundedHost in resOfScanner:
                
                if foundedHost in finalVulnerabilities:
                    pass
                else:
                    finalVulnerabilities[foundedHost] = {}
                    
                for portList in resOfScanner[foundedHost]:
                    portNum = list(portList.keys())[0]
                    vulnSet = list(portList.values())[0]
                    
                    if portNum in finalVulnerabilities[foundedHost]: 
                        finalVulnerabilities[foundedHost][portNum].update(vulnSet)
                    else:
                        finalVulnerabilities[foundedHost][portNum] = set(vulnSet)
        
        return finalVulnerabilities
                    

 
if __name__ == "__main__":
    #targetHost = sys.argv[1]
    
    scannerList = [VulnScannersFactory.NvdCVEScanner, VulnScannersFactory.MitreScanner]
    vulnApp = VulnApplicationManager("192.168.1.200", NmapScanner, scannerList)
    print(vulnApp.run())
