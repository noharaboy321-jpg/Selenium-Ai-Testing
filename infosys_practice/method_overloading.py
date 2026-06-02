from typing import overload, Union

class DataProcesor:
    @overload
    def generate(self, data: str):
        pass
    @overload
    def generate(self, data: int):
        pass
    def generate(self, data: str | int):
        
        if isinstance(data,str):
            print(data)
        elif isinstance(data,int):
            print(data * data)
        else:
            print('invalid datatype')
    
    
    
obj = DataProcesor()
obj.generate('new')
obj.generate(5)

#################################################################

class DataProcesor:
    def add(self, a: int, b: int, c: int = None) -> int:
        if c is None:
            return a + b
        return a + b + c
    
obj = DataProcesor()
print(obj.add(2,3))      # Output: 5        
print(obj.add(2,3,4))    # Output: 9