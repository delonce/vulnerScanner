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
    
    @abstractmethod
    def loadVulnerabilitiesDatabase(self, localDBPath:str):
        pass
    
    @abstractmethod
    def findVulnerabilities(self) -> list:
        pass
    
    def getServices(self) -> dict:
        return self.__serviceData
    
    def setServices(self, newServiceData):
        self.__serviceData = newServiceData