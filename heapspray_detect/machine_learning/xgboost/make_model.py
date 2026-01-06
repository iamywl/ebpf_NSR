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

folder_path = "./../../data/total/"
file_list = os.listdir(folder_path)
#print(file_list)

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
x = csv[['KMALLOC_TOTAL_COUNT',
         'KMALLOC_COUNT',
         'KFREE_COUNT',
         'KMALLOC_KIND',
         'KMALLOC_TOP_ENTROPY',
         'KMALLOC_TOP_GINI',
        ]]

# 타겟 데이터 column 설정
y = csv['DANGER']

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size = 0.2, random_state=50)

#xgb_v2 = XGBClassifier(objective='binary:logistic',n_estimators=500, eval_metric='logloss',learning_rate=0.01, max_depth=6, gamma=0.01 ,random_state = 32) #n_estimators=500 early_stopping_rounds=500
xgb_v2 = XGBClassifier() #n_estimators=500 early_stopping_rounds=500

# 모델 학습
xgb_v2.fit(x_train, y_train)

# 'model'은 학습이 완료된 XGBClassifier 모델입니다.
pickle.dump(xgb_v2, open("xgb_model.pkl", "wb"))
dump(xgb_v2,'xgb_model.joblib')
# 'model'은 학습이 완료된 XGBClassifier 모델입니다.
xgb_v2.save_model('xgb_model.json')
"""
with open("xgb_model.dill", "wb") as f:
     dill.dump(xgb_v2, f)
xgb_v2.save_model('xgb_model.json')
"""

# 테스트 데이터에 대한 예측을 만들어 y_pred에 저장
y_pred = xgb_v2.predict(x_test) 
print(y_pred)
import sklearn.metrics as metrics
print('accuracy', metrics.accuracy_score(y_test, y_pred) )
print('precision', metrics.precision_score(y_test, y_pred) )
print('recall', metrics.recall_score(y_test, y_pred) )
print('f1', metrics.f1_score(y_test, y_pred ))

feature_importances = xgb_v2.feature_importances_

# 특성 중요도를 출력합니다.
print("Feature Importances:")
for i, importance in enumerate(feature_importances):
    print(f"Feature {i}: {importance}")

# 만약 특성 이름이 있는 경우 (예: pandas DataFrame에서 학습한 경우)
# 특성 이름과 함께 출력할 수 있습니다.
if isinstance(x_train, pd.DataFrame):
    feature_names = x_train.columns
    importance_dict = dict(zip(feature_names, feature_importances))
    sorted_importance = sorted(importance_dict.items(), key=lambda item: item[1], reverse=True)
    
    print("\nFeature Importances (with feature names):")
    for feature, importance in sorted_importance:
        print(f"{feature}: {importance}")


