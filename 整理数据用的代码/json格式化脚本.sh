#!bin/sh
dire="./result"
if [ -d "$dire" ]; then
rm -r "$dire"
fi
mkdir "$dire"
for file in *.json
do 
python -m json.tool $file > "result/$file"
done
echo "json已批量格式化在result目录下"
