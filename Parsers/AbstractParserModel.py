from abc import ABCMeta, abstractmethod

class AbstractParserInterface(metaclass=ABCMeta):
    '''
    Интерфейс, описывающий поведение парсеров
    Общее поведение состоит в предварительной загрузке данных и паттернов
    '''
    
    @abstractmethod
    def parseData(self) -> dict:
        pass
    
    @abstractmethod
    def loadData(self, data:object):
        pass