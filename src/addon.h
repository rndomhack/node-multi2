#include <nan.h>

class Multi2 : public Nan::ObjectWrap
{
public:
	static NAN_MODULE_INIT(Init);

	struct SYSTEMKEY
	{
		uint32_t key1;
		uint32_t key2;
		uint32_t key3;
		uint32_t key4;
		uint32_t key5;
		uint32_t key6;
	};

	struct DATAKEY
	{
		uint32_t left;
		uint32_t right;
	};

private:
	Multi2();
	~Multi2();

	static Nan::Persistent<v8::Function> constructor;
	static NAN_METHOD(New);
	static NAN_METHOD(SetRound);
	static NAN_METHOD(SetSystemKey);
	static NAN_METHOD(SetInitialCbc);
	static NAN_METHOD(SetScrambleKey);
	static NAN_METHOD(Decrypt);

	static void KeySchedule(SYSTEMKEY &WorkKey, const SYSTEMKEY &SystemKey, DATAKEY &DataKey);

	static inline void Pi1(DATAKEY &Block);
	static inline void Pi2(DATAKEY &Block, const uint32_t k1);
	static inline void Pi3(DATAKEY &Block, const uint32_t k2, const uint32_t k3);
	static inline void Pi4(DATAKEY &Block, const uint32_t k4);

	bool m_HasSystemKey;
	bool m_HasInitialCbc;
	bool m_HasWorkKey;

	uint32_t m_Round;
	SYSTEMKEY m_systemKey;
	DATAKEY m_initialCbc;
	SYSTEMKEY m_workKeyOdd;
	SYSTEMKEY m_workKeyEven;
};
