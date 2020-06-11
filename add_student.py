from student import *
from random import randint
if __name__ == '__main__':
    for i in range(1000):
        student = Student(randint(0,99)) 
        t = student.gettime()
        student.enter_building(BUILDINGS[randint(1,3)], t)
