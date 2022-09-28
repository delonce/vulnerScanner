from Parsers.FindServices import FindServicesParser

class ParserGenerator():
    parserDict = {
        "services" : FindServicesParser()  
    }
    
    @classmethod
    def createParser(cls, parserType:str):
        return cls.parserDict[parserType]