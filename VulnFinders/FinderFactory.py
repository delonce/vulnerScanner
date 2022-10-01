from VulnFinders.MitreScanner import MitreVulnFinder
from VulnFinders.NvdCVEScanner import NvdVulnFinder

class VulnScannersFactory:
    '''
    Фабрика, позволяющая генерировать имеющиеся сканеры уязвимостей
    '''
    class MitreScanner:
        @staticmethod
        def createScanner(serviceData:str) -> MitreVulnFinder:
            return MitreVulnFinder(serviceData)
    
    class NvdCVEScanner:
        @staticmethod
        def createScanner(serviceData:str) -> MitreVulnFinder:
            return NvdVulnFinder(serviceData)