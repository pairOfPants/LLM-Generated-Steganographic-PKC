#!/bin/bash
#SBATCH --job-name=ollama_steg
#SBATCH --output=logs/%j.out
#SBATCH --error=logs/%j.err
#SBATCH --time=01:00:00
#SBATCH --mem=48G
#SBATCH --cluster=chip-gpu
#SBATCH --constraint='rtx_8000'
#SBATCH --gres=gpu:1


#Load the environment
module load ollama/0.21.2
module load python/3.12.4

#Start ollama server
ollama serve >> ollama_server.log 2>&1 &
sleep 5

#navigate to project's main directory
cd /umbc/rs/pi_cmarron/common/chip-project
source venv/bin/activate

python main.py