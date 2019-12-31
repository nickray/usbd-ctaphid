use core::{
    cmp::Ordering,
    fmt::{self, Debug},
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
    marker::PhantomData,
};
use heapless::{ArrayLength, Vec};
use serde::{
    ser::{Serialize, Serializer},
    de::{
        Deserialize,
        Deserializer,
        Error as _,
        SeqAccess,
        Visitor,
    },
};

#[derive(Clone, Default, Eq/*, Ord*/)]
pub struct ByteVec<N: ArrayLength<u8>> {
    bytes: Vec<u8, N>,
}

impl<N: ArrayLength<u8>> ByteVec<N> {

    /// Construct a new, empty `ByteVec<N>`.
    pub fn new() -> Self {
        ByteVec::from(Vec::new())
    }

    // /// Construct a new, empty `ByteVec<N>` with the specified capacity.
    // pub fn with_capacity(cap: usize) -> Self {
    //     ByteVec<N>::from(Vec::with_capacity(cap))
    // }

    /// Wrap existing bytes in a `ByteVec<N>`.
    pub fn from<T: Into<Vec<u8, N>>>(bytes: T) -> Self {
        ByteVec {
            bytes: bytes.into(),
        }
    }

    /// Unwrap the vector of byte underlying this `ByteVec<N>`.
    pub fn into_vec(self) -> Vec<u8, N> {
        self.bytes
    }

    #[doc(hidden)]
    pub fn into_iter(self) -> <Vec<u8, N> as IntoIterator>::IntoIter {
        self.bytes.into_iter()
    }
}

impl<N: ArrayLength<u8>> Debug for ByteVec<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(&self.bytes, f)
    }
}

impl<N: ArrayLength<u8>> AsRef<[u8]> for ByteVec<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<N: ArrayLength<u8>> AsMut<[u8]> for ByteVec<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl<N: ArrayLength<u8>> Deref for ByteVec<N> {
    type Target = Vec<u8, N>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl<N: ArrayLength<u8>> DerefMut for ByteVec<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

// impl Borrow<Bytes> for ByteVec<N> {
//     fn borrow(&self) -> &Bytes {
//         Bytes::new(&self.bytes)
//     }
// }

// impl BorrowMut<Bytes> for ByteVec<N> {
//     fn borrow_mut(&mut self) -> &mut Bytes {
//         unsafe { &mut *(&mut self.bytes as &mut [u8] as *mut [u8] as *mut Bytes) }
//     }
// }

impl<N: ArrayLength<u8>, Rhs> PartialEq<Rhs> for ByteVec<N>
where
    Rhs: ?Sized + AsRef<[u8]>,
{
    fn eq(&self, other: &Rhs) -> bool {
        self.as_ref().eq(other.as_ref())
    }
}

impl<N: ArrayLength<u8>, Rhs> PartialOrd<Rhs> for ByteVec<N>
where
    Rhs: ?Sized + AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Rhs) -> Option<Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}

impl<N: ArrayLength<u8>> Hash for ByteVec<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<N: ArrayLength<u8>> IntoIterator for ByteVec<N> {
    type Item = u8;
    type IntoIter = <Vec<u8, N> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.bytes.into_iter()
    }
}

impl<'a, N: ArrayLength<u8>> IntoIterator for &'a ByteVec<N> {
    type Item = &'a u8;
    type IntoIter = <&'a [u8] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.bytes.iter()
    }
}

impl<'a, N: ArrayLength<u8>> IntoIterator for &'a mut ByteVec<N> {
    type Item = &'a mut u8;
    type IntoIter = <&'a mut [u8] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.bytes.iter_mut()
    }
}


impl<N> Serialize for ByteVec<N>
where
    N: ArrayLength<u8>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self)
    }
}

// TODO: can we delegate to Vec<u8, N> deserialization instead of reimplementing?
impl<'de, N> Deserialize<'de> for ByteVec< N>
where
    N: ArrayLength<u8>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ValueVisitor<'de, N>(PhantomData<(&'de (), N)>);

        impl<'de, N> Visitor<'de> for ValueVisitor<'de, N>
        where
            N: ArrayLength<u8>,
        {
            // type Value = Vec<T, N>;
            type Value = ByteVec<N>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values: Vec<u8, N> = Vec::new();

                while let Some(value) = seq.next_element()? {
                    if values.push(value).is_err() {
                        return Err(A::Error::invalid_length(values.capacity() + 1, &self))?;
                    }
                }

                Ok(ByteVec::from(values))
            }
        }
        deserializer.deserialize_seq(ValueVisitor(PhantomData))
    }
}
