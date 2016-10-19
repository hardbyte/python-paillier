import abc
from .paillier import PaillierPublicKey, EncodedNumber


class BaseEncodingScheme(abc.ABC):
    """
    Abstract Base Class for all Encoding Schemes.

    Notes:
      Paillier encryption is only defined for non-negative integers less
      than :attr:`PaillierPublicKey.n`. Since we frequently want to use
      signed integers and/or floating point numbers (luxury!), values
      must be encoded as a valid integer before encryption.

      The operations of addition and multiplication [1]_ must be
      preserved under any encoding. Namely:

      1. Decode(Encode(a) + Encode(b)) = a + b
      2. Decode(Encode(a) * Encode(b)) = a * b

      for any real numbers a and b.

    Review Questions:
     - which properties are required for all possible encoding schemes?

    """

    @abc.abstractmethod
    def max_encoded(self, public_key: PaillierPublicKey):
        """Returns the largest number that can be encoded using
        this scheme.

        :param public_key:
        :return:
        """

    @abc.abstractproperty
    def signed(self) -> bool:
        """Exposes whether this Encoding Scheme supports signed numbers.
        """

    @abc.abstractmethod
    def valid_type(self, typ) -> bool:
        """Check whether the given type is supported for Encoding.
        """

    @abc.abstractmethod
    def encode(self, public_key: PaillierPublicKey, value) -> (int, dict):
        """
        Encode the given value to an integer representation.

        :returns the integer representation, and a dictionary of any public
            information. For example the number's precision.
        """


    @abc.abstractmethod
    def decode(self, public_key: PaillierPublicKey, encoded: int, **public_data):
        """Decode the integer representation.
        May require additional arguments containing additional information,
        e.g. exponent used to determine the precision.
        """


class PositiveIntegerEncoding(BaseEncodingScheme):
    """
    A simple encoding scheme that works for positive integers.
    """

    def valid_type(self, typ) -> bool:
        return issubclass(typ, int)

    @property
    def signed(self):
        return False

    def max_encoded(self, public_key: PaillierPublicKey):
        return public_key.max_int

    def encode(self, public_key, value):
        # the int is unchanged using this scheme
        return value, {}

    def decode(self, public_key, encoded, **public_data):
        return encoded


class SharedExponentEncoding(BaseEncodingScheme):
    """
    Encoding scheme that works for floating point numbers.

    Relies on knowing an `exponent` that sets the precision.

    Representing signed integers is relatively easy: we exploit the
    modular arithmetic properties of the Paillier scheme. We choose to
    represent only integers between
    +/-:attr:`~PaillierPublicKey.max_int`, where `max_int` is
    approximately :attr:`~PaillierPublicKey.n`/3 (larger integers may
    be treated as floats). The range of values between `max_int` and
    `n` - `max_int` is reserved for detecting overflows. This encoding
    scheme supports properties #1 and #2 above.

    Representing floating point numbers as integers is a harder task.
    Here we use a variant of fixed-precision arithmetic. In fixed
    precision, you encode by multiplying every float by a large number
    (e.g. 1e6) and rounding the resulting product. You decode by
    dividing by that number. However, this encoding scheme does not
    satisfy property #2 above: upon every multiplication, you must
    divide by the large number. In a Paillier scheme, this is not
    possible to do without decrypting. For some tasks, this is
    acceptable or can be worked around, but for other tasks this can't
    be worked around.

    In our scheme, the "large number" is allowed to vary, and we keep
    track of it. It is:

      :attr:`BASE` ** :attr:`exponent`

    One number has many possible encodings; this property can be used
    to mitigate the leak of information due to the fact that
    :attr:`exponent` is never encrypted.

    """

    def valid_type(self, typ) -> bool:
        return issubclass(typ, (float, int))

    @property
    def signed(self):
        return True

    def max_encoded(self, public_key: PaillierPublicKey):
        """Maximum int that may safely be stored.

        This can be increased, if you are happy to redefine "safely" and lower
        the chance of detecting an integer overflow.
        """
        return public_key.max_int // 3 - 1

    def encode(self, public_key, value, **kwargs):
        """

        Supported Optional Keyword Arguments:

        precision (float):
          If *value* is a float then *precision* is the maximum
          **absolute** error allowed when encoding *value*. Defaults
          to encoding *value* exactly.

        :param public_key:
        :param value:
        :param kwargs:
        :return:
        """

        def encode(cls, public_key, scalar, precision=None, max_exponent=None):
            """Return an encoding of an int or float.

            This encoding is carefully chosen so that it supports the same
            operations as the Paillier cryptosystem.

            If *scalar* is a float, first approximate it as an int, `int_rep`:

                scalar = int_rep * (:attr:`BASE` ** :attr:`exponent`),

            for some (typically negative) integer exponent, which can be
            tuned using *precision* and *max_exponent*. Specifically,
            :attr:`exponent` is chosen to be equal to or less than
            *max_exponent*, and such that the number *precision* is not
            rounded to zero.

            Having found an integer representation for the float (or having
            been given an int `scalar`), we then represent this integer as
            a non-negative integer < :attr:`~PaillierPublicKey.n`.

            Paillier homomorphic arithemetic works modulo
            :attr:`~PaillierPublicKey.n`. We take the convention that a
            number x < n/3 is positive, and that a number x > 2n/3 is
            negative. The range n/3 < x < 2n/3 allows for overflow
            detection.

            Args:
              public_key (PaillierPublicKey): public key for which to encode
                (this is necessary because :attr:`~PaillierPublicKey.n`
                varies).
              scalar: an int or float to be encrypted.
                If int, it must satisfy abs(*value*) <
                :attr:`~PaillierPublicKey.n`/3.
                If float, it must satisfy abs(*value* / *precision*) <<
                :attr:`~PaillierPublicKey.n`/3
                (i.e. if a float is near the limit then detectable
                overflow may still occur)
              precision (float): Choose exponent (i.e. fix the precision) so
                that this number is distinguishable from zero. If `scalar`
                is a float, then this is set so that minimal precision is
                lost. Lower precision leads to smaller encodings, which
                might yield faster computation.
              max_exponent (int): Ensure that the exponent of the returned
                `EncryptedNumber` is at most this.

            Returns:
              EncodedNumber: Encoded form of *scalar*, ready for encryption
              against *public_key*.
            """
            # Calculate the maximum exponent for desired precision
            if precision is None:
                if isinstance(scalar, int):
                    prec_exponent = 0
                elif isinstance(scalar, float):
                    # Encode with *at least* as much precision as the python float
                    # What's the base-2 exponent on the float?
                    bin_flt_exponent = math.frexp(scalar)[1]

                    # What's the base-2 exponent of the least significant bit?
                    # The least significant bit has value 2 ** bin_lsb_exponent
                    bin_lsb_exponent = bin_flt_exponent - cls.FLOAT_MANTISSA_BITS

                    # What's the corresponding base BASE exponent? Round that down.
                    prec_exponent = math.floor(bin_lsb_exponent / cls.LOG2_BASE)
                else:
                    raise TypeError("Don't know the precision of type %s."
                                    % type(scalar))
            else:
                prec_exponent = math.floor(math.log(precision, cls.BASE))

            # Remember exponents are negative for numbers < 1.
            # If we're going to store numbers with a more negative
            # exponent than demanded by the precision, then we may
            # as well bump up the actual precision.
            if max_exponent is None:
                exponent = prec_exponent
            else:
                exponent = min(max_exponent, prec_exponent)

            int_rep = int(round(scalar * pow(cls.BASE, -exponent)))

            if abs(int_rep) > public_key.max_int:
                raise ValueError('Integer needs to be within +/- %d but got %d'
                                 % (public_key.max_int, int_rep))

            # Wrap negative numbers by adding n
            return cls(public_key, int_rep % public_key.n, exponent)


        return int_repr, {}

    def decode(self, public_key, encoded, **public_data):
        return encoded
