import os 

content=os.walk("quarantined_data")
for root,dirs,files in content:
    for file in files:
        print(os.path.join(root,file))