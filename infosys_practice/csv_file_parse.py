import csv
import glob

all_rows = []
header = None

# Read all CSV files
for file in glob.glob("data/*.csv"):
    with open(file, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)

        try:
            file_header = next(reader)         # read header row
        except StopIteration:
            continue                            # skip empty file

        if not file_header:
            continue                            # skip header-only blank line

        if header is None:
            header = file_header               # save header from first file

        for row in reader:
            if any(row):                        # skip fully blank rows
                all_rows.append(row)

# Remove duplicates
# unique_rows = list({tuple(row): row for row in all_rows}.values())
unique_rows = []

for row in all_rows:
    if row not in unique_rows:
        unique_rows.append(row)


# Write master.csv
if not header:
    print("No data found in any CSV file.")
else:
    with open("master.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(unique_rows)

    print(f"Total rows read    : {len(all_rows)}")
    print(f"Duplicates removed : {len(all_rows) - len(unique_rows)}")
    print(f"Unique rows written: {len(unique_rows)}")
    print("master.csv created successfully!")
######################################################################################
import glob
import pandas as pd

all_files = glob.glob("data/*.csv")

df_list = []
for file in all_files:
    df_list.append(pd.read_csv(file))

master_pd = pd.concat(df_list, ignore_index=True)

master_pd.dropna(how="all", inplace=True)
master_pd.drop_duplicates(inplace=True)  

master_pd.to_csv("master.csv", index=False)

print("master.csv created successfully!")