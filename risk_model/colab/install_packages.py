# Install required Python packages and mount Google Drive
# !pip install --upgrade pip
# !pip install torch==2.3.0 torchvision==0.18.0 torchaudio==2.3.0 --index-url https://download.pytorch.org/whl/cu118
# !pip install torch-geometric==2.5.3 networkx==3.3 pandas==2.2.2 numpy==1.26.4 scikit-learn==1.4.2 matplotlib==3.9.0 seaborn==0.13.2
# !pip install transformers==4.41.2 sentence-transformers==2.7.0 datasets==2.20.0
# !pip install fastapi==0.111.0 uvicorn==0.30.0 pydantic==2.7.4 requests==2.32.3
# !pip install openai==1.35.0
from google.colab import drive
drive.mount('/content/drive')
