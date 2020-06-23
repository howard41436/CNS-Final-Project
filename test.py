from student import Student
from cdc import CDC
from datetime import datetime
import random
BUILDING_NUM = 3
BUILDINGS = {1: "DerTian", 2: "MingDa", 3: "XiaoFu"}
if __name__ == '__main__':
    for i in range(1, 25):
        print(f'date 6/{i}')
        for _ in range(10):
            student_id = random.randrange(100)
            student = Student(student_id)
            building = BUILDINGS[random.randrange(1, BUILDING_NUM)]
            timestamp = f"202006{i:02d}0800"
            verdict = student.enter_building(building, timestamp)
            if not verdict:
                print("student failed to enter!")
                exit(0)
    cdc = CDC()
    patient_footprint, quarantine_list = cdc.trigger_diagnosed_event([1])
    print('Patient footprint:', *patient_footprint, sep = '\n')
    print('Quarantine list:')
    print(quarantine_list)