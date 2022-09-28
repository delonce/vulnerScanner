import nmap

from PortScanners.AbstractPortScanner import AbstractScanner

class NmapScanner(AbstractScanner):
    '''
    Сканер открытых портов и поиска версий запущенных сервисов
    '''
    
    def __init__(self, targetHost:str, keys:list=[]):
        self.__keys = keys
        super().__init__(targetHost=targetHost)
    
    def startScanning(self) -> object:
        '''
        Запускает сканирование с помощью nmap,
        проверяет успешность выполнения команды
        Возвращает список просканированных хостов
        '''
        
        stringKeys = " ".join(self.__keys)
        
        try:
            nmapSc = nmap.PortScanner()
            nmapSc.scan(self.getHost(), arguments=stringKeys)
        except Exception as e:
            print(e)
            return None
        
        return nmapSc
        

    def createPortList(self) -> list:
        '''
        Возвращает список открытых портов по хостам, найденных утилитой nmap
        '''
        scanningResult = self.startScanning()
        if not scanningResult: return []
        
        services = []

        for host in scanningResult.all_hosts():
            hostInfo = []
            
            if "tcp" in scanningResult[host]:
                tcpInfo = scanningResult[host]["tcp"]
                hostInfo.append(tcpInfo)
                
            if "udp" in scanningResult[host]:
                udpInfo = scanningResult[host]["udp"]
                hostInfo.append(udpInfo)
            
            services.append({host : hostInfo})
        
        return services
                



