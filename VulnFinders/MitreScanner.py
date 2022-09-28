import os
import pandas as pd

from VulnFinders.AbstractVulnFinder import AbstractVulnerabilitiesFinder

class MitreVulnFinder(AbstractVulnerabilitiesFinder):
    '''
    Класс, находящий уязвимости из базы данных MITRE
    Функции:
        load - загрузка основной БД уязвимостей
        find - главная функция, обнаруживающивая уязвимости в бд
        __create - создаёт пару с помощью zip с названием уязвимости и её описанием
    '''    
    def loadVulnerabilitiesDatabase(self, localDBPath:str="allitems.csv"):
        '''
        Загружает необходимую базу уязвимостей
        '''
        self.__vulnDatabase = pd.read_csv(os.path.join(self.DBPATH, localDBPath), encoding="ISO-8859-1")
    
    def findVulnerabilities(self) -> dict:
        '''
        Главная функция, перебирает все активные сервисы и производит поиск в БД узявимостей с помощью pandas
        '''
        resultVulnDict = {}
        
        for host in self.getServices():
            resultVulnDict[host] = []
        
            for openPorts in self.getServices()[host]:
                product = openPorts["product"]
                version = openPorts["version"]
                
                if len(version) > 1:
                    version = version[:-2]
                
                if not product:
                    if not version:
                        continue
                    else:
                        product = openPorts["name"]
                        if "?" in product:
                            continue
                    
                
                findings = self.__vulnDatabase[self.__vulnDatabase["Description"].str.contains(product) 
                                               & self.__vulnDatabase["Description"].str.contains(version)]
                
                vulList = self.__createListOfVulns(findings)
                resultVulnDict[host].append({openPorts["port"] : vulList})
        
        return resultVulnDict
    
    @staticmethod
    def __createListOfVulns(vulDB:str) -> list:
        '''
        Возвращает названия уязвимостей в виде списка
        '''
        return list(vulDB["Name"])
    
        