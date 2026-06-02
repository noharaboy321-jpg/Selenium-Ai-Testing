"""Write a Python function to reverse the individual words of a string while keeping their exact sentence positions identical """

def reverse_word(sentence: str) -> str:
	
	result=" ".join([word[::-1] for word in sentence.split(" ")])
	
print(reverse_word('xyz abc pqr'))