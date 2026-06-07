import os, json, numpy as np, torch, torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

SEQ_FILE   = "data/sequences.npy"
LABEL_FILE = "data/labels.npy"
VOCAB_FILE = "data/vocab.json"
MODEL_DIR  = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

class IntentLSTM(nn.Module):
    def __init__(self, vocab_size, embed_dim, hidden_size, num_layers):
        super().__init__()
        self.embed  = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm   = nn.LSTM(embed_dim, hidden_size, num_layers, batch_first=True, dropout=0.3)
        self.fc     = nn.Linear(hidden_size, 1)
        self.sigmoid = nn.Sigmoid()
    def forward(self, x):
        x = self.embed(x)
        _, (h, _) = self.lstm(x)
        return self.sigmoid(self.fc(h[-1])).squeeze(-1)


if __name__ == "__main__":
    seqs   = np.load(SEQ_FILE)
    labels = np.load(LABEL_FILE)
    vocab  = json.load(open(VOCAB_FILE))
    
    print(f"Dataset: {len(seqs)} users | Vocab: {len(vocab)} | High-risk: {labels.mean()*100:.1f}%")
    
    X = torch.tensor(seqs, dtype=torch.long)
    y = torch.tensor(labels, dtype=torch.float32)
    
    split = int(0.8 * len(X))
    train_ds = TensorDataset(X[:split], y[:split])
    val_ds   = TensorDataset(X[split:], y[split:])
    train_dl = DataLoader(train_ds, batch_size=64, shuffle=True)
    val_dl   = DataLoader(val_ds,   batch_size=64)
    
    cfg = {"vocab_size": len(vocab), "embed_dim": 64, "hidden_size": 128, "num_layers": 2, "seq_len": 30}
    model = IntentLSTM(**{k:v for k,v in cfg.items() if k != "seq_len"})
    
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.BCELoss()
    
    print("Training...")
    for epoch in range(20):
        model.train()
        total_loss = 0
        for xb, yb in train_dl:
            optimizer.zero_grad()
            pred = model(xb)
            loss = criterion(pred, yb)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
    
        model.eval()
        correct = 0
        with torch.no_grad():
            for xb, yb in val_dl:
                pred = model(xb)
                correct += ((pred > 0.5) == yb.bool()).sum().item()
        acc = correct / len(val_ds) * 100
        print(f"Epoch {epoch+1:2d}/20 | Loss: {total_loss/len(train_dl):.4f} | Val Acc: {acc:.1f}%")
    
    torch.save(model.state_dict(), f"{MODEL_DIR}/lstm_model.pt")
    json.dump(cfg, open(f"{MODEL_DIR}/lstm_config.json","w"), indent=2)
    print("\nModel saved! Training complete.")
    