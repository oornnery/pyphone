echo "Build PJSIP"
echo "#"
tar -xvf pjproject-2.14.1.tar.gz
cd pjproject-2.14.1
# Build PJSIP
./configure --disable-video --disable-v4l2 CFLAGS="-fPIC" CXXFLAGS="-fPIC"
make dep && make
sudo make install

cd pjsip-apps/src/swig/python
make
sudo make install
pip install .
