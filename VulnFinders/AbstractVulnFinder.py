from abc import ABCMeta, abstractmethod

class AbstractVulnerabilitiesFinder(metaclass=ABCMeta):
    '''
    Абстрактный класс для поисковиков уязвимостей
    Включает в себя:
    Конструктор для загрузки словаря с открытыми сервисами
    Функцию загрузки БД уязвимостей
    Функцию поиска уязвимостей в бд
    '''
    DBPATH = "VulnFinders/databases"
    
    def __init__(self, serviceData:dict):
        self.__serviceData = serviceData
    
    def _serviceGenerator(self) -> tuple:
        '''
        Генератор записей с активными сервисамии для дальнейшей их обработки
        '''
        for host in self.getServices():
    
            for openPorts in self.getServices()[host]:
                product = openPorts["product"]
                extra = openPorts["extra"]
                version = openPorts["version"]
                port = openPorts["port"]
                
                if len(version) > 1:
                    version = version[:-2]
                
                if not product:
                    if not version:
                        continue
                    else:
                        product = openPorts["name"]
                        if "?" in product:
                            continue
                
                yield (product, version, extra, port, host)
    
    @abstractmethod
    def loadVulnerabilitiesDatabase(self):
        pass
    
    @abstractmethod
    def findVulnerabilities(self) -> list:
        pass
    
    def getServices(self) -> dict:
        return self.__serviceData
    
    def setServices(self, newServiceData):
        self.__serviceData = newServiceData