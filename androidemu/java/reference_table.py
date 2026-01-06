from .jni_ref import jobject


class ReferenceTable:
    """
    :type _table dict[int, jobject|None]
    """

    def __init__(self, start=1, max_entries=1024):
        self._table = dict()
        self._start = start
        self._size = max_entries

    def set(self, idx, newobj):
        if not isinstance(newobj, jobject):
            raise ValueError("Expected a jobject.")

        if idx not in self._table:
            raise ValueError("Expected a index.")

        self._table[idx] = newobj

    def add(self, obj):
        if not isinstance(obj, jobject):
            raise ValueError("Expected a jobject.")

        # Search a free index.
        index = self._start
        while index in self._table:
            index += 1

        # Add to table.
        self._table[index] = obj

        return index

    def remove(self, obj):
        index = None
        for idx, item in self._table.items():
            if item is obj:
                index = idx
                break

        if index is None:
            return False

        del self._table[index]
        return True

    def remove_by_id(self, idx):
        if idx in self._table:
            del self._table[idx]
            return True
        return False

    def get(self, idx):
        if idx not in self._table:
            return None
        r = self._table[idx]
        return r

    def in_range(self, idx):
        return self._start <= idx < self._start + self._size

    def clear(self):
        self._table.clear()
