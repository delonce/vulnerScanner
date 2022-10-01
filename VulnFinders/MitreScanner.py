import os
import pandas as pd

from VulnFinders.AbstractVulnFinder import AbstractVulnerabilitiesFinder

class MitreVulnFinder(AbstractVulnerabilitiesFinder):
    '''
    Класс, находящий уязвимости из базы данных MITRE
    '''
    LOCALPATH = "allitems.csv"
    
    def loadVulnerabilitiesDatabase(self):
        '''
        Загружает необходимую базу уязвимостей
        '''
        self.__vulnDatabase = pd.read_csv(os.path.join(self.DBPATH, self.LOCALPATH), encoding="ISO-8859-1")
    
    def findVulnerabilities(self) -> dict:
        '''
        Главная функция, перебирает все активные сервисы и производит поиск в БД узявимостей с помощью pandas
        '''
        resultVulnDict = {}
        
        for product, version, extra, port, host in self._serviceGenerator():
            if host not in resultVulnDict:
                resultVulnDict[host] = []
                
            findings = self.__vulnDatabase[self.__vulnDatabase["Description"].str.contains(product) 
                                           & self.__vulnDatabase["Description"].str.contains(version)
                                           & self.__vulnDatabase["Description"].str.contains(extra)]
            
            vulList = self.__createListOfVulns(findings)
            resultVulnDict[host].append({port : vulList})
    
        return resultVulnDict
    
    @staticmethod
    def __createListOfVulns(vulDB:str) -> list:
        '''
        Возвращает названия уязвимостей в виде списка
        '''
        return list(vulDB["Name"])
    
        