class A:
    def execute(self):
        print("Class A executing")

class B(A):
    def execute(self):
        print("Class B executing")
        super().execute()  # Where does this go? Look at the MRO chain!

class C(A):
    def execute(self):
        print("Class C executing")
        super().execute()

class D(B, C):
    def execute(self):
        print("Class D executing")
        super().execute()

# --- Checking the MRO ---
# You can inspect the search path of any class using the .__mro__ attribute
print(f"MRO for Class D: {D.__mro__}")
