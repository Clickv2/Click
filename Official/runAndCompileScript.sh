
if [ "$#" -ne 1 ]; then
	echo "please give the NAME of the click script (expected in ./scripts/) as a CL argument"
else
	cd click-2.0.1/
	make
	make elemlist
	cd ..
	click-2.0.1/userlevel/click ./scripts/"$1"
fi
