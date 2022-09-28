from VulnFinders.MitreScanner import MitreVulnFinder

class VulnScannersFactory:
    class MitreScanner:
        @staticmethod
        def createScanner(serviceData:str) -> MitreVulnFinder:
            return MitreVulnFinder(serviceData)