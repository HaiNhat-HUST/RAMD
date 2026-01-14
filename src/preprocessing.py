from ramd_implementation import config
from ramd_implementation.features import process_dataset
import argparse 

def main():
    parser = argparse.ArgumentParser(description="RAMD Testing Module")

    parser.add_argument('--benign-report-folder', type=str, help="Path to benign report folder for preprocessing")
    parser.add_argument('--malware-report-folder', type=str, help="Path to malware report folder for preprocessing")
    parser.add_argument('--output-file', type=str, help="Output file path for the processed dataset. Ex: data/processed/processed_dataset.csv")
    args = parser.parse_args()

    process_dataset(args.benign_report_folder, args.malware_report_folder, output_file=args.output_file)

if __name__ == "__main__":
    main()