<script setup>
import { computed } from 'vue';
import qrcode from 'qrcode-generator';

const props = defineProps({
  value: { type: String, default: '' },
  size: { type: Number, default: 176 },
});

// 输出内联 SVG，不需要 data URI，也不依赖 canvas。
const svg = computed(() => {
  if (!props.value) return '';
  try {
    const qr = qrcode(0, 'M');
    qr.addData(props.value);
    qr.make();
    return qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
  } catch {
    return '';
  }
});
</script>

<template>
  <div class="qr" :style="{ width: `${size}px` }" role="img" aria-label="两步验证二维码">
    <div v-if="svg" class="qr-image" v-html="svg" />
    <p v-else class="qr-empty">无法生成二维码，请使用下方的密钥手动添加。</p>
  </div>
</template>

<style scoped>
.qr { flex: none; }
.qr-image {
  padding: 8px;
  border-radius: 10px;
  background: #fff;
  box-shadow: 0 1px 3px var(--shadow-color);
}
.qr-image :deep(svg) { display: block; width: 100%; height: auto; }
.qr-empty {
  padding: 12px;
  border: 1px dashed var(--border-strong);
  border-radius: 10px;
  color: var(--muted);
  font-size: 11.5px;
  line-height: 1.6;
}
</style>
