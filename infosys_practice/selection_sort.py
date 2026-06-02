def selection_sort(arr):
    for i in range(len(arr)):
        mini = i
        for j in range(i+1, len(arr)):
            if arr[j]<arr[mini]:
                mini = j
        arr[i],arr[mini]=arr[mini],arr[i]
    return arr
    
print(selection_sort([11,12,31,2,3,54,1]))
            
def insertion_sort(arr):
    for i in range(1,len(arr)):
        key=arr[i]
        j=i-1
        while j>=0 and arr[j]>key:
            arr[j+1]=arr[j]
            j-=1
        arr[j+1]=key
    return arr
print(insertion_sort([11,12,31,2,3,54,1]))

def bubble_sort(arr):
    for i in range(len(arr)):
        for j in range(0,len(arr)-i-1):
            if arr[j]>arr[j+1]:
                arr[j+1],arr[j]=arr[j],arr[j+1]
    return arr
print(bubble_sort([11,12,31,2,3,54,1]))
                