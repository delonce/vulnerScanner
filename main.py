import sys

from PortScanners.NmapPortScanner import NmapScanner
from Parsers.GeneratorOfParsers import ParserGenerator
from VulnFinders.FinderFactory import VulnScannersFactory


class VulnApplicationManager:
    '''
    Менеджер управления приложением
    Создаёт сканеры портов, парсеры, обрабатывает результаты их работы
    При наличии информации об активных сервисах, передаёт её далее к поиску в бд
    '''
    def __init__(self, host:str, portScanner, *args):
        self.__portScanner = portScanner(host, ["-sV"])
        self.__host = host
        self.__vulnScFactories = args      
        self.__vulnScanners = []
    
    def findVulnerabilities(self):
        '''
        Запуск имеющихся сканеров на поиск уязвимостей
        '''
        services = self.__findActiveServices()
        
        if not services:
            return None
        else:
            for vulnScanner in self.__createVulnFinders(services):
                vulnScanner.loadVulnerabilitiesDatabase()
                print(vulnScanner.findVulnerabilities())
                
    
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
    
    def __createVulnFinders(self, serviceData:str) -> list:
        '''
        С помощью списка фабрик создаёт сканеры уязвимостей,
        передаёт в них информацию об активных сервисах
        '''
        vulnScanners = []
        
        for vulnScFactory in self.__vulnScFactories:
            vulnSc = vulnScFactory.createScanner(serviceData)
            vulnScanners.append(vulnSc)
        
        return vulnScanners
 
if __name__ == "__main__":
    targetHost = sys.argv[1]
    
    vulnApp = VulnApplicationManager(targetHost, NmapScanner, VulnScannersFactory.MitreScanner)
    vulnApp.findVulnerabilities()
