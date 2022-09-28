from abc import ABCMeta, abstractmethod

class AbstractScanner(metaclass=ABCMeta):
    '''
    Абстрактный класс сканера портов, основная цель -
    найти работающие сервисы на хосте
    
    __host: IP-адрес цели
    '''
    
    def __init__(self, targetHost:str):
        self.__host = targetHost
        
    @abstractmethod
    def startScanning(self):
        pass

    @abstractmethod
    def createPortList(self) -> list:
        pass
    
    def getHost(self) -> str:
        return self.__host
    
    def setHost(self, newHost:str):
        self.__host = newHost