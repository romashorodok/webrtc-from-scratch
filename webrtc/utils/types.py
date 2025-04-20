import inspect
from typing import Type


def impl_protocol(protocol: Type):
    def decorator(cls):
        protocol_methods = {
            method
            for method in dir(protocol)
            if callable(getattr(protocol, method, None))
            and not (method.startswith("__") and method.endswith("__"))
        }

        cls_methods = {
            method for method in dir(cls) if callable(getattr(cls, method, None))
        }

        if not protocol_methods.issubset(cls_methods):
            missing_methods = protocol_methods - cls_methods
            raise TypeError(
                f"Class {cls.__name__} is missing methods required by the protocol: {missing_methods}"
            )

        for method in protocol_methods:
            protocol_method_sig = inspect.signature(getattr(protocol, method))
            cls_method_sig = inspect.signature(getattr(cls, method))
            if protocol_method_sig != cls_method_sig:
                raise TypeError(
                    f"Signature of method '{method}' in class '{cls.__name__}' does not match the protocol."
                )

        return cls

    return decorator
