import os
import sys
import numpy as np
import torch
import torch.nn.functional as F

# Add MalConv2 to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'MalConv2'))

from MalConvGCT_nocat import MalConvGCT

class MalConvDetector:
    def __init__(self, checkpoint_path=None):
        if checkpoint_path is None:
            checkpoint_path = os.path.join(os.path.dirname(__file__), '..', 'MalConv2', 'malconvGCT_nocat.checkpoint')
        
        self.model = MalConvGCT(channels=256, window_size=256, stride=64)
        
        if os.path.exists(checkpoint_path):
            checkpoint = torch.load(checkpoint_path, map_location='cpu')
            self.model.load_state_dict(checkpoint['model_state_dict'], strict=False)
            print("Loaded MalConv checkpoint successfully.")
        else:
            raise FileNotFoundError(f"Checkpoint not found at {checkpoint_path}")
        
        self.model.eval()

    def predict(self, file_path, threshold=0.5):
        """
        Predict if a file is malicious using MalConv.
        
        Args:
            file_path (str): Path to the binary file
            threshold (float): Threshold for malicious classification (default 0.5)
        
        Returns:
            dict: {'prediction': 'malicious' or 'benign', 'confidence': float}
        """
        try:
            # Read file as bytes
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if len(data) == 0:
                return {'prediction': 'benign', 'confidence': 0.0, 'error': 'Empty file'}
            
            # Convert bytes to tensor: uint8 -> int16 + 1 (1-256 range, 0 is padding)
            data_np = np.frombuffer(data, dtype=np.uint8).astype(np.int16) + 1
            data_tensor = torch.tensor(data_np, dtype=torch.long)
            
            # Add batch dimension
            data_tensor = data_tensor.unsqueeze(0)
            
            with torch.no_grad():
                model_output = self.model(data_tensor)
                # MalConvGCT returns tuple: (outputs, penultimate_activ, conv_active)
                if isinstance(model_output, tuple):
                    outputs = model_output[0]
                else:
                    outputs = model_output
                # outputs shape: (batch, 2) for binary classification
                probs = F.softmax(outputs, dim=-1)
                malicious_prob = probs[0, 1].item()  # Probability of class 1 (malicious)
                benign_prob = probs[0, 0].item()     # Probability of class 0 (benign)

                prediction = 'malicious' if malicious_prob >= threshold else 'benign'
                
                confidence = malicious_prob if prediction == 'malicious' else benign_prob
                return {
                    'prediction': prediction,
                    'confidence': confidence
                }
                
        except Exception as e:
            return {'prediction': 'error', 'confidence': 0.0, 'error': str(e)}