# Import
import os
import pandas as pd 
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from xgboost import XGBClassifier
import xgboost as xgb
import matplotlib.pyplot as plt
import pickle
from joblib import dump
import dill

folder_path = "./../../data/csv/"
file_list = os.listdir(folder_path)
file_list

# 하나의 CSV 파일로 합치기
csv = pd.DataFrame([]) # 빈 데이터프레임 생성
for i in file_list:
    try:
        target_file = folder_path + i
        print(target_file)
        temp = pd.read_csv(target_file, sep=',', encoding='utf-8')
    except pd.errors.EmptyDataError:
        continue
    else:
        csv = pd.concat([csv, temp], ignore_index=True)

# Check
print(type(csv))

# 특징 데이터 columns설정
x = csv[['SYSCALL_TOTAL_COUNT',
         'SYSCALL_ARGUMENT_SIMILAR',
         'SYSCALL_KIND_SIMILAR',
         'SYSCALL_KIND',
         'SYSCALL_TOP1',
         'SYSCALL_TOP2',
         'SYSCALL_TOP3',
         'SYSCALL_TOP4',
         'SYSCALL_TOP5',
         'SYSCALL_TOP6']]

# 타겟 데이터 column 설정
y = csv['DANGER']

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size = 0.25, random_state=32)

xgb_v2 = XGBClassifier(objective='binary:logistic',booster='gbtree',n_estimators=100, learning_rate=0.1, max_depth=4, reg_lambda=20 ,gamma=0.1 ,random_state = 32) #n_estimators=500 early_stopping_rounds=500

# 모델 학습
xgb_v2.fit(x_train, y_train)

# 'model'은 학습이 완료된 XGBClassifier 모델입니다.
pickle.dump(xgb_v2, open("xgb_model.pkl", "wb"))
dump(xgb_v2,'xgb_model.joblib')
# 'model'은 학습이 완료된 XGBClassifier 모델입니다.
with open("xgb_model.dill", "wb") as f:
     dill.dump(xgb_v2, f)
xgb_v2.save_model('xgb_model.json')

# 테스트 데이터에 대한 예측을 만들어 y_pred에 저장
#y_pred = xgb_v2.predict(x_test) 
y_pred = []
y_pred_prob = xgb_v2.predict_proba(x_test)
for y_val in y_pred_prob:
    if y_val[1] > 0.95:
        y_pred.append(1)
    else:
        y_pred.append(0)
#print(y_pred_prob)
#print(y_pred)
import sklearn.metrics as metrics
print('accuracy', metrics.accuracy_score(y_test, y_pred) )
print('precision', metrics.precision_score(y_test, y_pred) )
print('recall', metrics.recall_score(y_test, y_pred) )
print('f1', metrics.f1_score(y_test, y_pred ))

