# Import
import os
import pandas as pd 
from sklearn.model_selection import train_test_split
from sklearn.ensemble import AdaBoostClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
import dill
import pickle
import json


folder_path = "./../../data/csv/"
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

# AdaBoost 모델 학습
model = AdaBoostClassifier()
model.fit(x_train, y_train)

# 예측
y_pred = model.predict(x_test)

# 성능 평가
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')

print(f"Accuracy: {accuracy}")
print(f"Precision: {precision}")
print(f"Recall: {recall}")
print(f"F1 Score: {f1}")

# 모델 저장

# 1. joblib으로 저장
joblib.dump(model, 'adaboost_model.joblib')

pickle.dump(model, open("adaboost_model.pkl", "wb"))

# 3. dill로 저장
with open('adaboost_model.dill', 'wb') as f:
    dill.dump(model, f)

#model.save_model('adaboost_model.json')

print("Model saved in joblib, pkl, dill, and json formats.")

feature_importances = model.feature_importances_

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

