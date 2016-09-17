#include <nan.h>

class Multi2 : public Nan::ObjectWrap
{
public:
	static NAN_MODULE_INIT(Init)
	{
		v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
		tpl->SetClassName(Nan::New("Multi2").ToLocalChecked());
		tpl->InstanceTemplate()->SetInternalFieldCount(1);

		Nan::SetPrototypeMethod(tpl, "setRound", SetRound);
		Nan::SetPrototypeMethod(tpl, "setSystemKey", SetSystemKey);
		Nan::SetPrototypeMethod(tpl, "setInitialCbc", SetInitialCbc);
		Nan::SetPrototypeMethod(tpl, "setScrambleKey", SetScrambleKey);
		Nan::SetPrototypeMethod(tpl, "decrypt", Decrypt);

		constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
		target->Set(Nan::New("Multi2").ToLocalChecked(), Nan::GetFunction(tpl).ToLocalChecked());
	}

	struct SYSTEMKEY
	{
		uint32_t key1;
		uint32_t key2;
		uint32_t key3;
		uint32_t key4;
		uint32_t key5;
		uint32_t key6;
		uint32_t key7;
		uint32_t key8;
	};

	struct DATAKEY
	{
		uint32_t left;
		uint32_t right;
	};

private:
	explicit Multi2():
		m_hasSystemKey(false),
		m_hasInitialCbc(false),
		m_hasWorkKey(false),
		m_round(4),
		m_systemKey({ 0 }),
		m_initialCbc({ 0 }),
		m_workKeyOdd({ 0 }),
		m_workKeyEven({ 0 })
	{};
	~Multi2() {};

	static NAN_METHOD(New)
	{
		Multi2 *obj = new Multi2();
		obj->Wrap(info.This());
		info.GetReturnValue().Set(info.This());
	}

	static NAN_METHOD(SetRound)
	{
		Multi2 *obj = Nan::ObjectWrap::Unwrap<Multi2>(info.Holder());

		if (!info[0]->IsUint32()) {
			Nan::ThrowTypeError("Invalid round");
			return;
		}

		obj->m_round = info[0]->Uint32Value();
	}

	static NAN_METHOD(SetSystemKey)
	{
		Multi2 *obj = Nan::ObjectWrap::Unwrap<Multi2>(info.Holder());

		if (!node::Buffer::HasInstance(info[0])) {
			Nan::ThrowTypeError("buffer is not buffer");
			return;
		}

		v8::Local<v8::Object> buffer = info[0]->ToObject();

		if (node::Buffer::Length(buffer) != 32) {
			Nan::ThrowError("buffer length is not 32");
			return;
		}

		uint8_t *data = (uint8_t *)node::Buffer::Data(buffer);

		obj->m_systemKey = {
			ReadUInt32BE(data),
			ReadUInt32BE(data + 4),
			ReadUInt32BE(data + 8),
			ReadUInt32BE(data + 12),
			ReadUInt32BE(data + 16),
			ReadUInt32BE(data + 20),
			ReadUInt32BE(data + 24),
			ReadUInt32BE(data + 28)
		};

		obj->m_hasSystemKey = true;
	}

	static NAN_METHOD(SetInitialCbc)
	{

		Multi2 *obj = Nan::ObjectWrap::Unwrap<Multi2>(info.Holder());

		if (!node::Buffer::HasInstance(info[0])) {
			Nan::ThrowTypeError("buffer is not buffer");
			return;
		}

		v8::Local<v8::Object> buffer = info[0]->ToObject();

		if (node::Buffer::Length(buffer) != 8) {
			Nan::ThrowError("buffer length is not 8");
			return;
		}

		uint8_t *data = (uint8_t *)node::Buffer::Data(buffer);

		obj->m_initialCbc = {
			ReadUInt32BE(data),
			ReadUInt32BE(data + 4)
		};

		obj->m_hasInitialCbc = true;
	}

	static NAN_METHOD(SetScrambleKey) {
		Multi2 *obj = Nan::ObjectWrap::Unwrap<Multi2>(info.Holder());

		if (!node::Buffer::HasInstance(info[0])) {
			Nan::ThrowTypeError("buffer is not buffer");
			return;
		}

		v8::Local<v8::Object> buffer = info[0]->ToObject();

		if (node::Buffer::Length(buffer) != 16) {
			Nan::ThrowError("buffer length is not 16");
			return;
		}

		uint8_t *data = (uint8_t *)node::Buffer::Data(buffer);

		DATAKEY scrambleKeyOdd = { 
			ReadUInt32BE(data),
			ReadUInt32BE(data + 4)
		};

		DATAKEY scrambleKeyEven = {
			ReadUInt32BE(data + 8),
			ReadUInt32BE(data + 12)
		};

		KeySchedule(obj->m_workKeyOdd, obj->m_systemKey, scrambleKeyOdd);
		KeySchedule(obj->m_workKeyEven, obj->m_systemKey, scrambleKeyEven);

		obj->m_hasWorkKey = true;
	}

	static NAN_METHOD(Decrypt) {
		Multi2 *obj = Nan::ObjectWrap::Unwrap<Multi2>(info.Holder());

		if (!node::Buffer::HasInstance(info[0])) {
			Nan::ThrowTypeError("buffer is not buffer");
			return;
		}

		if (!info[1]->IsBoolean()) {
			Nan::ThrowTypeError("isEven is not boolean");
			return;
		}

		if (!obj->m_hasSystemKey) {
			Nan::ThrowError("systemKey is not set");
			return;
		}

		if (!obj->m_hasInitialCbc) {
			Nan::ThrowError("initialCbc is not set");
			return;
		}

		if (!obj->m_hasWorkKey) {
			Nan::ThrowError("scrambleKey is not set");
			return;
		}

		v8::Local<v8::Object> buffer = info[0]->ToObject();
		bool isEven = info[1]->BooleanValue();

		uint8_t *data = (uint8_t *)node::Buffer::Data(buffer);
		const uint32_t dataLength = (uint32_t)node::Buffer::Length(buffer);

		const SYSTEMKEY &workKey = isEven ? obj->m_workKeyEven : obj->m_workKeyOdd;
		DATAKEY cbc = obj->m_initialCbc;

		const uint32_t remainStart = dataLength & 0xFFFFFFF8UL;
		const uint32_t remainLength = dataLength & 0x00000007UL;

		DATAKEY src, dest;
		uint8_t *pLeft, *pRight;
		uint32_t bytesRead = 0;

		while (bytesRead < remainStart) {
			pLeft = data + bytesRead;
			pRight = data + bytesRead + 4;

			src.left = dest.left = ReadUInt32BE(pLeft);
			src.right = dest.right = ReadUInt32BE(pRight);

			for (uint32_t round = 0UL; round < obj->m_round; round++) {
				Pi4(dest, workKey.key8);
				Pi3(dest, workKey.key6, workKey.key7);
				Pi2(dest, workKey.key5);
				Pi1(dest);
				Pi4(dest, workKey.key4);
				Pi3(dest, workKey.key2, workKey.key3);
				Pi2(dest, workKey.key1);
				Pi1(dest);
			}


			dest.left ^= cbc.left;
			dest.right ^= cbc.right;

			cbc.left = src.left;
			cbc.right = src.right;

			WriteUInt32BE(dest.left, pLeft);
			WriteUInt32BE(dest.right, pRight);

			bytesRead += 8UL;
		}

		if (remainLength > 0) {
			for (uint32_t round = 0UL; round < obj->m_round; round++) {
				Pi1(cbc);
				Pi2(cbc, workKey.key1);
				Pi3(cbc, workKey.key2, workKey.key3);
				Pi4(cbc, workKey.key4);
				Pi1(cbc);
				Pi2(cbc, workKey.key5);
				Pi3(cbc, workKey.key6, workKey.key7);
				Pi4(cbc, workKey.key8);
			}

			switch (remainLength) {
				default: __assume(0);
				case 7: *(data + bytesRead + 6) ^= (cbc.right >> 8) & 0xFF;
				case 6: *(data + bytesRead + 5) ^= (cbc.right >> 16) & 0xFF;
				case 5: *(data + bytesRead + 4) ^= (cbc.right >> 24) & 0xFF;
				case 4: *(data + bytesRead + 3) ^= cbc.left & 0xFF;
				case 3: *(data + bytesRead + 2) ^= (cbc.left >> 8) & 0xFF;
				case 2: *(data + bytesRead + 1) ^= (cbc.left >> 16) & 0xFF;
				case 1: *(data + bytesRead) ^= (cbc.left >> 24) & 0xFF;
			}
		}
	}

	static inline Nan::Persistent<v8::Function> & constructor()
	{
		static Nan::Persistent<v8::Function> my_constructor;
		return my_constructor;
	}

	static void KeySchedule(SYSTEMKEY &workKey, const SYSTEMKEY &systemKey, DATAKEY &dataKey) {
		Pi1(dataKey);

		Pi2(dataKey, systemKey.key1);
		workKey.key1 = dataKey.left;

		Pi3(dataKey, systemKey.key2, systemKey.key3);
		workKey.key2 = dataKey.right;

		Pi4(dataKey, systemKey.key4);
		workKey.key3 = dataKey.left;

		Pi1(dataKey);
		workKey.key4 = dataKey.right;

		Pi2(dataKey, systemKey.key5);
		workKey.key5 = dataKey.left;

		Pi3(dataKey, systemKey.key6, systemKey.key7);
		workKey.key6 = dataKey.right;
		
		Pi4(dataKey, systemKey.key8);
		workKey.key7 = dataKey.left;

		Pi1(dataKey);
		workKey.key8 = dataKey.right;
	}

	static inline const uint32_t ReadUInt32BE(const uint8_t *src)
	{
		return (src[0] << 24) | (src[1] << 16) | (src[2] << 8) | src[3];
	}

	static inline void WriteUInt32BE(const uint32_t src, uint8_t *dest)
	{
		dest[0] = (uint8_t)((src >> 24) & 0xFF);
		dest[1] = (uint8_t)((src >> 16) & 0xFF);
		dest[2] = (uint8_t)((src >> 8) & 0xFF);
		dest[3] = (uint8_t)(src & 0xFF);
	}

	static inline const uint32_t LeftRotate(const uint32_t value, const uint32_t rotate)
	{
		return (value << rotate) | (value >> (32UL - rotate));
	}

	static inline void Pi1(DATAKEY &block)
	{
		block.right ^= block.left;
	}

	static inline void Pi2(DATAKEY &block, const uint32_t k1)
	{
		const uint32_t y = block.right + k1;
		const uint32_t z = LeftRotate(y, 1UL) + y - 1UL;

		block.left ^= LeftRotate(z, 4UL) ^ z;
	}

	static inline void Pi3(DATAKEY &block, const uint32_t k2, const uint32_t k3)
	{
		const uint32_t y = block.left + k2;
		const uint32_t z = LeftRotate(y, 2UL) + y + 1UL;
		const uint32_t a = LeftRotate(z, 8UL) ^ z;
		const uint32_t b = a + k3;
		const uint32_t c = LeftRotate(b, 1UL) - b;

		block.right ^= (LeftRotate(c, 16UL) ^ (c | block.left));
	}

	static inline void Pi4(DATAKEY &block, const uint32_t k4)
	{
		const uint32_t y = block.right + k4;

		block.left ^= (LeftRotate(y, 2UL) + y + 1UL);
	}

	bool m_hasSystemKey;
	bool m_hasInitialCbc;
	bool m_hasWorkKey;

	uint32_t m_round;
	SYSTEMKEY m_systemKey;
	DATAKEY m_initialCbc;
	SYSTEMKEY m_workKeyOdd;
	SYSTEMKEY m_workKeyEven;
};

NODE_MODULE(addon, Multi2::Init);
