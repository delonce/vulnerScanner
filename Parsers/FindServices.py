from Parsers.AbstractParserModel import AbstractParserInterface

class FindServicesParser(AbstractParserInterface):
    def parseData(self) -> dict:
        '''
        Возвращает словарь, где ключи - адрес хоста, 
        а значение - список словарей с информацией о сервисах,
        запущенных на пк
        '''
        openServices = {}
        
        for hostInfo in self.__scannerOutData:
            address = list(hostInfo.keys())[0]
            openServices[address] = []
            
            for portInfo in hostInfo.values():
                for portsDict in portInfo:
                    for port in portsDict:
                        portInfo = {
                            "port" : port,
                            "extra" : portsDict[port]["extrainfo"],
                            "name" : portsDict[port]["name"],
                            "product" : portsDict[port]["product"], 
                            "version" : portsDict[port]["version"]
                            }
                        
                        openServices[address].append(portInfo)
        
        return openServices
                    
    def loadData(self, data:list):
        '''
        Получаем список с открытыми портами и работающими сервисами на них
        '''
        self.__scannerOutData = data