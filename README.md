# N.A.P.T — Nawres Autonomous Pentest Tool

AI-powered autonomous penetration testing platform (PFE Cybersécurité).

## Pipeline

Nmap Scan → Qdrant RAG (CVE Search) → Gemma 4 AI Analysis → Exploit Suggestion → PDF Report

## Stack

- **Backend**: FastAPI + Python 3.10
- **AI Model**: Google Gemma 4 via OpenRouter API
- **RAG**: Qdrant v1.9.0 + fastembed (30 CVEs indexed)
- **Frontend**: React 18 + Vite
- **Auth**: JWT

## Installation (automated)

git clone https://github.com/Nawresbouali/napt.git
cd napt
bash install.sh

This will automatically:
- Create Python virtual environment
- Install all dependencies
- Download and start Qdrant
- Index 30 critical CVEs (EternalBlue, Log4Shell, SMBGhost...)
- Build the frontend

## Run

bash start.sh

- Backend API: http://localhost:8000
- Frontend UI: http://localhost:5173
- API Docs: http://localhost:8000/docs

## Default credentials

Username: admin
Password: admin123

## Features

- Network Scan: Nmap integration (TCP/UDP/aggressive)
- RAG CVE Search: Semantic search on CVE database
- AI Analysis: Gemma 4 vulnerability analysis
- Exploit Suggestion: AI-generated exploitation guidance
- Dashboard: Real-time scan monitoring
- PDF Report: Auto-generated audit report

## Requirements

- Linux (Ubuntu/Debian/WSL2)
- Python 3.10+
- Node.js 18+
- Nmap (sudo apt install nmap)
- OpenRouter API key (included in install)
