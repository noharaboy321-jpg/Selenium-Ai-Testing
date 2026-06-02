import numpy as np

def cosine_similarity(str1: str, str2: str) -> float
	
	vector1 = np.array([0.1,0.3,0.7])
	vector2 = np.array([0.12, 0.29, 0.68])

	dot_product = np.dot(vector1, vector2)
	norm1 = np.linalg(vector1)
	norm2 = np.linalg(vector2)
	
	return dot_product / (norm1 * norm2)

def semantic_search_algorism():
	actual = "test is good but the development is not good"
	AI = "because the tester is good but developer is not good."
	
	score = cosine_similarity(actual,AI)
	assert score > 0.85, "Result is not matched and deviation is more than 0.85"
	
	
	