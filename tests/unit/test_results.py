from sigmatcher.results import Class, Field, Method


def test_field_java_round_trip() -> None:
    field = Field.from_java_representation("counter:I")
    assert field.name == "counter"
    assert field.type == "I"
    assert field.to_java_representation() == "counter:I"
    assert field.java == "counter:I"


def test_method_java_round_trip() -> None:
    method = Method.from_java_representation("doWork(Ljava/lang/String;)V")
    assert method.name == "doWork"
    assert method.argument_types == "Ljava/lang/String;"
    assert method.return_type == "V"
    assert method.to_java_representation() == "doWork(Ljava/lang/String;)V"
    assert method.java == "doWork(Ljava/lang/String;)V"


def test_class_name_and_java_round_trip() -> None:
    clazz = Class.from_full_name("com.example.network.ConnectionManager")
    assert clazz.name == "ConnectionManager"
    assert clazz.package == "com.example.network"
    assert clazz.full_name == "com.example.network.ConnectionManager"
    assert clazz.to_java_representation() == "Lcom/example/network/ConnectionManager;"

    from_java = Class.from_java_representation("Lcom/example/network/ConnectionManager;")
    assert from_java == clazz
